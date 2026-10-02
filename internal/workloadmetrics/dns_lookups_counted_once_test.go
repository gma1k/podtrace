package workloadmetrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/diagnose/detector"
	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
)

func dnsLookupCount(t *testing.T, reg *prometheus.Registry) uint64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	var n uint64
	for _, f := range families {
		if f.GetName() != "podtrace_workload_dns_latency_seconds" {
			continue
		}
		for _, m := range f.GetMetric() {
			n += m.GetHistogram().GetSampleCount()
		}
	}
	return n
}

func TestALookupIsCountedOnceOnTheEventPath(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, e := range []*events.Event{
		{Type: events.EventDNSQuery, K8s: enriched()},
		{Type: events.EventDNS, LatencyNS: 150_000_000, K8s: enriched()},
	} {
		base, ok := sink.baseLabelValues(e)
		if !ok {
			t.Fatal("fixture is unattributed")
		}
		if !sink.record(e, base) {
			t.Fatalf("%v was not accounted for", e.Type)
		}
	}
	if got := dnsLookupCount(t, reg); got != 1 {
		t.Errorf("one query and its response recorded %d lookups; the zero-latency query halves every share and mean", got)
	}
}

func TestALookupIsCountedOnceOnTheKernelPath(t *testing.T) {
	sink, reg := kernelSink(t)
	sink.IngestKernel([]kernelagg.Row{
		kernelRow(events.EventDNSQuery, 0, kernelagg.BucketIndex(0), 40, 0, 0),
		kernelRow(events.EventDNS, 0, kernelagg.BucketIndex(150_000_000), 40, 40*150_000_000, 0),
	})
	if got := dnsLookupCount(t, reg); got != 40 {
		t.Errorf("40 lookups recorded as %d", got)
	}
}

func TestEverySlowKernelAggregatedLookupCountsAsSlow(t *testing.T) {
	rows := []kernelagg.Row{
		kernelRow(events.EventDNSQuery, 0, kernelagg.BucketIndex(0), 60, 0, 0),
		kernelRow(events.EventDNS, 0, kernelagg.BucketIndex(150_000_000), 60, 60*150_000_000, 0),
	}
	active := evaluateOverKernelRows(t, rows, rows)
	if !hasIssue(active, detector.IDDNSSlowLookupRate) {
		t.Fatalf("every lookup answered in 150ms and dns.slow_lookup_rate did not fire: %v", active)
	}
	for _, issue := range active {
		if issue.ID == detector.IDDNSSlowLookupRate && !strings.Contains(issue.Message, "100.0% of 60 lookups") {
			t.Errorf("the queries diluted the share: %q", issue.Message)
		}
	}
}
