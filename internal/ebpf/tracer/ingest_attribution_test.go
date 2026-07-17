package tracer

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/podtrace/podtrace/internal/attribution"
	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/ebpf/cache"
	"github.com/podtrace/podtrace/internal/events"
)

// deadPID is a syntactically valid pid that is overwhelmingly unlikely to
// exist, so the /proc fallback yields nothing and only the correlator can
// attribute an event carrying it.
const deadPID = uint32(4194301)

// newDispatchTestTracer builds a Tracer wired for a processAndDispatch
// call: an empty target-cgroup set (so loadCgroupIDs is non-nil-safe) and
// a fresh attribution table.
func newDispatchTestTracer() *Tracer {
	ttl := time.Duration(config.CacheTTLSeconds) * time.Second
	t := &Tracer{
		processNameCache: cache.NewLRUCache(config.CacheMaxSize, ttl),
		attributionTable: attribution.New(time.Minute, 64),
	}
	t.storeCgroupIDs(map[uint64]struct{}{})
	return t
}

// dispatchOne pushes one event through the real ingest entry point with
// cgroup filtering disabled (allow-all) and returns the event as the
// downstream consumer would receive it.
func dispatchOne(t *testing.T, tr *Tracer, ev *events.Event) *events.Event {
	t.Helper()
	ch := make(chan *events.Event, 1)
	var collected, filtered, parsed atomic.Int64
	var filteringDisabled atomic.Bool
	filteringDisabled.Store(true)
	ec := &eventCounters{
		collected:         &collected,
		filtered:          &filtered,
		parsed:            &parsed,
		filteringDisabled: &filteringDisabled,
	}
	tr.processAndDispatch(context.Background(), ev, ch, nil, ec, time.Now())
	select {
	case got := <-ch:
		return got
	default:
		t.Fatal("event was not dispatched to the channel")
		return nil
	}
}

// attrCounter reads podtrace_attribution_total{source,event} from the
// default registry (metricsexporter registers there) so the test asserts
// the real cross-package metric the ingest path emits, not a stub.
func attrCounter(t *testing.T, source, event string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, mf := range families {
		if mf.GetName() != "podtrace_attribution_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			var gotSource, gotEvent string
			for _, l := range m.GetLabel() {
				switch l.GetName() {
				case "source":
					gotSource = l.GetValue()
				case "event":
					gotEvent = l.GetValue()
				}
			}
			if gotSource == source && gotEvent == event {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// TestIngest_CorrelatorBeatsProcForDeadDNSPid is the end-to-end-shaped
// proof the kind run could not give: a DNS event carrying a pid that is
// NOT in /proc still gets the right process name, and it can only have
// come from the correlator. This is exactly the short-lived-client case
// the whole feature exists for.
func TestIngest_CorrelatorBeatsProcForDeadDNSPid(t *testing.T) {
	tr := newDispatchTestTracer()
	const cgroup = uint64(7)

	// A live-context UDP send from the same pid+cgroup seeds the table
	// (this is what a kprobe producer with a real comm would do).
	seed := dispatchOne(t, tr, &events.Event{
		PID: deadPID, CgroupID: cgroup, ProcessName: "nslookup", Type: events.EventUDPSend,
	})
	if seed.ProcessName != "nslookup" {
		t.Fatalf("seed event comm mutated to %q", seed.ProcessName)
	}

	before := attrCounter(t, "correlator", "dns")

	// The cgroup_skb DNS query arrives later with a zeroed comm and a pid
	// that /proc can no longer resolve.
	dns := dispatchOne(t, tr, &events.Event{
		PID: deadPID, CgroupID: cgroup, Type: events.EventDNSQuery,
	})
	if dns.ProcessName != "nslookup" {
		t.Fatalf("dead-pid DNS event ProcessName = %q, want nslookup (correlator)", dns.ProcessName)
	}
	if delta := attrCounter(t, "correlator", "dns") - before; delta != 1 {
		t.Fatalf("attribution_total{correlator,dns} delta = %v, want 1", delta)
	}
}

// TestIngest_QUICAttributedAtIngest covers the QUIC/HTTP3 path the plan
// called out: an EventHTTP3 with a zeroed comm (as bpf/http3.c ships it)
// is attributed at ingest and counted under event="quic".
func TestIngest_QUICAttributedAtIngest(t *testing.T) {
	tr := newDispatchTestTracer()
	const cgroup = uint64(11)

	dispatchOne(t, tr, &events.Event{
		PID: deadPID, CgroupID: cgroup, ProcessName: "curl", Type: events.EventUDPSend,
	})

	before := attrCounter(t, "correlator", "quic")
	quic := dispatchOne(t, tr, &events.Event{
		PID: deadPID, CgroupID: cgroup, Type: events.EventHTTP3,
	})
	if quic.ProcessName != "curl" {
		t.Fatalf("HTTP/3 event ProcessName = %q, want curl (correlator)", quic.ProcessName)
	}
	if delta := attrCounter(t, "correlator", "quic") - before; delta != 1 {
		t.Fatalf("attribution_total{correlator,quic} delta = %v, want 1", delta)
	}
}

// TestIngest_DeadPidNoTableIsNone proves the honest negative: with no
// correlator entry and a dead pid, /proc cannot save it and the event is
// counted as unattributed rather than mislabeled.
func TestIngest_DeadPidNoTableIsNone(t *testing.T) {
	tr := newDispatchTestTracer()
	before := attrCounter(t, "none", "dns")
	ev := dispatchOne(t, tr, &events.Event{
		PID: deadPID, CgroupID: 99, Type: events.EventDNSQuery,
	})
	if ev.ProcessName != "" {
		t.Fatalf("dead-pid unattributed event ProcessName = %q, want empty", ev.ProcessName)
	}
	if delta := attrCounter(t, "none", "dns") - before; delta != 1 {
		t.Fatalf("attribution_total{none,dns} delta = %v, want 1", delta)
	}
}

// TestIngest_CorrelatorDisabledFallsBackToProc proves the kill-switch
// reproduces the pre-correlator behavior: with the correlator off, a DNS
// event whose pid the table knows is NOT attributed from the table, it
// falls to /proc, and a dead pid yields none.
func TestIngest_CorrelatorDisabledFallsBackToProc(t *testing.T) {
	tr := newDispatchTestTracer()
	tr.attributionCorrelatorDisabled = true
	const cgroup = uint64(7)

	// Seed the table exactly as the enabled path would.
	dispatchOne(t, tr, &events.Event{
		PID: deadPID, CgroupID: cgroup, ProcessName: "nslookup", Type: events.EventUDPSend,
	})

	beforeCorr := attrCounter(t, "correlator", "dns")
	beforeNone := attrCounter(t, "none", "dns")

	dns := dispatchOne(t, tr, &events.Event{
		PID: deadPID, CgroupID: cgroup, Type: events.EventDNSQuery,
	})
	if dns.ProcessName != "" {
		t.Fatalf("correlator-disabled dead-pid DNS ProcessName = %q, want empty (proc only)", dns.ProcessName)
	}
	if delta := attrCounter(t, "correlator", "dns") - beforeCorr; delta != 0 {
		t.Fatalf("correlator counted while disabled: delta = %v", delta)
	}
	if delta := attrCounter(t, "none", "dns") - beforeNone; delta != 1 {
		t.Fatalf("attribution_total{none,dns} delta = %v, want 1", delta)
	}
}

// TestIngest_KernelCommCountedAndFeedsTable proves the common path emits
// source=event_comm and that this is what seeds the correlator (not the
// later correlator/proc reads).
func TestIngest_KernelCommCountedAndFeedsTable(t *testing.T) {
	tr := newDispatchTestTracer()
	before := attrCounter(t, "event_comm", "other")
	dispatchOne(t, tr, &events.Event{
		PID: deadPID, CgroupID: 5, ProcessName: "wget", Type: events.EventUDPSend,
	})
	if delta := attrCounter(t, "event_comm", "other") - before; delta != 1 {
		t.Fatalf("attribution_total{event_comm,other} delta = %v, want 1", delta)
	}
	if name, ok, _ := tr.attributionTable.Lookup(deadPID, 5); !ok || name != "wget" {
		t.Fatalf("kernel-comm event did not seed the table: name=%q ok=%v", name, ok)
	}
}
