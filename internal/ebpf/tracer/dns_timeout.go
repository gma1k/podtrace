package tracer

import (
	"bytes"
	"context"
	"time"

	"golang.org/x/sys/unix"

	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/logger"
	"github.com/gma1k/podtrace/internal/metricsexporter"
	"github.com/gma1k/podtrace/internal/safeconv"
	"github.com/gma1k/podtrace/internal/sanitize"
	"github.com/gma1k/podtrace/internal/validation"
	"go.uber.org/zap"
)

// dnsFlowKey mirrors struct dns_flow_key in bpf/maps.h.
type dnsFlowKey struct {
	CgroupID uint64
	Txid     uint32
	Pad      uint32
}

// dnsQueryState mirrors struct dns_query_state in bpf/maps.h.
type dnsQueryState struct {
	TsNS        uint64
	PID         uint32
	QType       uint32
	ServerIP    uint32
	Transport   uint8
	MultiServer uint8
	ClientPort  uint16
	Comm        [16]byte
	Name        [128]byte
	ServerIP6   [16]byte
	LastNS      uint64
}

const (
	dnsTimeoutThresholdNS   = 5 * uint64(time.Second)
	dnsTimeoutSweepEvery    = 2 * time.Second
	dnsInflightCountMapName = "dns_inflight_cgroup"
)

func monotonicNowNS() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	if ts.Sec < 0 || ts.Nsec < 0 {
		return 0
	}
	return safeconv.Int64ToUint64(ts.Sec)*uint64(time.Second) + safeconv.Int64ToUint64(ts.Nsec)
}

// runDNSTimeoutSweeper periodically scans dns_inflight for queries that never
// got a response and emits a synthetic EVENT_DNS "timeout" for each, then drops
// the entry.
func (t *Tracer) runDNSTimeoutSweeper(ctx context.Context, eventChan chan<- *events.Event) {
	ticker := time.NewTicker(dnsTimeoutSweepEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.sweepDNSTimeouts(ctx, eventChan)
			t.recordDNSDrops()
		}
	}
}

func (t *Tracer) recordDNSDrops() {
	if t.collection == nil {
		return
	}
	m := t.collection.Maps["dns_drops"]
	if m == nil {
		return
	}
	var perCPU []uint64
	if err := m.Lookup(uint32(0), &perCPU); err != nil {
		return
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	if total > t.lastDNSDrops {
		metricsexporter.AddDNSDrops(total - t.lastDNSDrops)
		logger.Debug("DNS records dropped (map/ringbuf full)", zap.Uint64("delta", total-t.lastDNSDrops))
	}
	t.lastDNSDrops = total
}

func (t *Tracer) sweepDNSTimeouts(ctx context.Context, eventChan chan<- *events.Event) {
	if t.collection == nil {
		return
	}
	m := t.collection.Maps["dns_inflight"]
	if m == nil {
		return
	}
	now := monotonicNowNS()
	if now == 0 {
		return
	}

	live, complete := t.sweepDNSInflight(ctx, eventChan, m.Iterate(), m, now)
	if complete {
		t.syncDNSInflightCounts(live)
	}
}

// dnsMapIterator is the part of a BPF map iterator the sweeper walks.
type dnsMapIterator interface {
	Next(key, value any) bool
	Err() error
}

// dnsMapDeleter is the part of the dns_inflight map the sweeper deletes from.
type dnsMapDeleter interface {
	Delete(key any) error
}

// sweepDNSInflight emits a timeout for every in-flight query that has waited
// too long, deletes those entries, and counts the queries each cgroup still
// has in flight.
func (t *Tracer) sweepDNSInflight(ctx context.Context, eventChan chan<- *events.Event, iter dnsMapIterator, m dnsMapDeleter, now uint64) (map[uint64]int32, bool) {
	var key, staleKey dnsFlowKey
	var val dnsQueryState
	var stale []dnsFlowKey
	live := map[uint64]int32{}

	for iter.Next(&key, &val) {
		live[key.CgroupID]++
		if val.TsNS == 0 || now <= val.LastNS || now-val.LastNS <= dnsTimeoutThresholdNS {
			continue
		}
		age := now - val.TsNS
		staleKey = key
		stale = append(stale, staleKey)

		ev := t.buildDNSTimeoutEvent(key, val, now, age)
		if ev == nil {
			continue
		}
		if !t.offerDNSTimeout(ctx, eventChan, ev) {
			return nil, false
		}
	}
	iterErr := iter.Err()
	if iterErr != nil {
		logger.Debug("dns_inflight iterate error", zap.Error(iterErr))
	}
	for i := range stale {
		if err := m.Delete(&stale[i]); err == nil {
			live[stale[i].CgroupID]--
		}
	}
	return live, iterErr == nil
}

// dnsInflightCountMap is the part of the dns_inflight_cgroup map the
// sweeper rewrites.
type dnsInflightCountMap interface {
	Put(key, value any) error
	Delete(key any) error
}

// syncDNSInflightCounts rewrites each cgroup's count of in-flight queries
// from the walk the sweep just did. The probes keep the count as they add
// and answer queries, but the entries the sweep removes and the ones the
// map evicts are invisible to them, so without this the count would only
// grow and eventually refuse every new query of that cgroup.
func (t *Tracer) syncDNSInflightCounts(live map[uint64]int32) {
	m := t.collection.Maps[dnsInflightCountMapName]
	if m == nil {
		return
	}
	syncDNSInflightCountsFrom(m.Iterate(), m, live)
}

// syncDNSInflightCountsFrom rewrites the counts from live, removing the
// cgroups iter lists that have nothing in flight any more. A failed walk
// writes nothing, since it may have missed cgroups whose stale counts would
// then stay.
func syncDNSInflightCountsFrom(iter dnsMapIterator, m dnsInflightCountMap, live map[uint64]int32) {
	var cgroup uint64
	var count int32
	var known []uint64
	for iter.Next(&cgroup, &count) {
		known = append(known, cgroup)
	}
	if err := iter.Err(); err != nil {
		logger.Debug("dns_inflight_cgroup iterate error", zap.Error(err))
		return
	}
	writeDNSInflightCounts(m, known, live)
}

// writeDNSInflightCounts stores every positive count in live and removes
// the cgroups in known that no longer have a query in flight.
func writeDNSInflightCounts(m dnsInflightCountMap, known []uint64, live map[uint64]int32) {
	for _, cgroup := range known {
		if live[cgroup] <= 0 {
			_ = m.Delete(cgroup)
		}
	}
	for cgroup, count := range live {
		if count > 0 {
			_ = m.Put(cgroup, count)
		}
	}
}

// buildDNSTimeoutEvent turns one timed-out dns_inflight entry into an event,
// applying the same protections as the main pipeline.
func (t *Tracer) buildDNSTimeoutEvent(key dnsFlowKey, val dnsQueryState, now, age uint64) *events.Event {
	ev := &events.Event{
		Timestamp:    now,
		PID:          val.PID,
		Type:         events.EventDNS,
		LatencyNS:    age,
		Error:        events.DNSErrorTimeout,
		CgroupID:     key.CgroupID,
		TCPState:     val.QType,
		DNSServerIP:  val.ServerIP,
		DNSServerIP6: val.ServerIP6,
		DNSTransport: val.Transport,
		Target:       sanitize.Terminal(string(bytes.TrimRight(val.Name[:], "\x00"))),
		Details:      "timeout",
		ProcessName:  string(bytes.TrimRight(val.Comm[:], "\x00")),
	}
	t.attributeProcessName(ev)
	ev.ProcessName = validation.SanitizeProcessName(ev.ProcessName)
	if t.piiRedactor != nil {
		t.piiRedactor.Redact(ev)
	}
	if !t.cgroupAllows(ev) {
		return nil
	}
	return ev
}

// offerDNSTimeout hands a timeout event to the pipeline without blocking,
// counting it as dropped when the channel is full like any other event.
func (t *Tracer) offerDNSTimeout(ctx context.Context, eventChan chan<- *events.Event, ev *events.Event) bool {
	select {
	case <-ctx.Done():
		return false
	case eventChan <- ev:
	default:
		metricsexporter.RecordRingBufferDrop()
		t.reportDrop("channel_full", 1)
	}
	return true
}
