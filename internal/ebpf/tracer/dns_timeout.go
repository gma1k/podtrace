package tracer

import (
	"bytes"
	"context"
	"time"

	"golang.org/x/sys/unix"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/logger"
	"github.com/podtrace/podtrace/internal/metricsexporter"
	"github.com/podtrace/podtrace/internal/safeconv"
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
	TsNS      uint64
	PID       uint32
	QType     uint32
	ServerIP  uint32
	Transport uint8
	Pad       [3]uint8
	Comm      [16]byte
	Name      [128]byte
	ServerIP6 [16]byte
}

const (
	dnsTimeoutThresholdNS = 5 * uint64(time.Second)
	dnsTimeoutSweepEvery  = 2 * time.Second
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

	var key, staleKey dnsFlowKey
	var val dnsQueryState
	var stale []dnsFlowKey

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		if val.TsNS == 0 || now <= val.TsNS {
			continue
		}
		age := now - val.TsNS
		if age <= dnsTimeoutThresholdNS {
			continue
		}
		ev := &events.Event{
			Timestamp:   now,
			PID:         val.PID,
			Type:        events.EventDNS,
			LatencyNS:   age,
			CgroupID:    key.CgroupID,
			TCPState:    val.QType,
			Target:      string(bytes.TrimRight(val.Name[:], "\x00")),
			Details:     "timeout",
			ProcessName: string(bytes.TrimRight(val.Comm[:], "\x00")),
		}
		if t.piiRedactor != nil {
			t.piiRedactor.Redact(ev)
		}
		select {
		case <-ctx.Done():
			return
		case eventChan <- ev:
		default:
		}
		staleKey = key
		stale = append(stale, staleKey)
	}
	if err := iter.Err(); err != nil {
		logger.Debug("dns_inflight iterate error", zap.Error(err))
	}
	for i := range stale {
		_ = m.Delete(&stale[i])
	}
}
