package workloadmetrics

import (
	"context"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/diagnose/detector"
	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
)

func dnsVariant(source uint8, class uint8, failed bool) uint8 {
	v := source&0x7 | (class&0x7)<<3
	if failed {
		v |= 1 << 6
	}
	return v
}

func dnsSink(t *testing.T, kernelAggregation, packetCapture bool) (*Sink, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{
		NativeHistograms:  true,
		KernelAggregation: kernelAggregation,
		DNSPacketCapture:  packetCapture,
		Lookup:            kernelTestLookup,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return sink, reg
}

func counterByLabel(t *testing.T, reg *prometheus.Registry, family, label string) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	for _, m := range gather(t, reg, family) {
		out[labelsOf(m)[label]] += m.GetCounter().GetValue()
	}
	return out
}

func sameCounts(got map[string]float64, want map[string]float64) bool {
	if len(got) != len(want) {
		return false
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

func TestKernelRowsCountLookupsByAnswer(t *testing.T) {
	sink, reg := dnsSink(t, true, true)
	bucket := kernelagg.BucketIndex(1_000_000)
	sink.IngestKernel([]kernelagg.Row{
		kernelRow(events.EventDNS, dnsVariant(events.DNSSourceUDP, 0, false), bucket, 10, 10_000_000, 0),
		kernelRow(events.EventDNS, dnsVariant(events.DNSSourceUDP, 1, false), bucket, 20, 20_000_000, 0),
		kernelRow(events.EventDNS, dnsVariant(events.DNSSourceTCP, 2, true), bucket, 3, 3_000_000, 0),
		kernelRow(events.EventDNS, dnsVariant(events.DNSSourceUDP, 3, true), bucket, 2, 2_000_000, 0),
		kernelRow(events.EventDNS, dnsVariant(events.DNSSourceEncrypted, 0, false), bucket, 50, 0, 0),
		kernelRow(events.EventDNS, dnsVariant(events.DNSSourceLibc, 2, true), bucket, 4, 4_000_000, 0),
	})

	want := map[string]float64{"NOERROR": 10, "NXDOMAIN": 20, "SERVFAIL": 3, "REFUSED": 2}
	if got := counterByLabel(t, reg, "podtrace_workload_dns_lookups_total", "rcode"); !sameCounts(got, want) {
		t.Errorf("lookups %v, want %v: encrypted connections and getaddrinfo calls the packets already show are not lookups", got, want)
	}
	if got := dnsLookupCount(t, reg); got != 35 {
		t.Errorf("latency observed %d lookups, want 35", got)
	}
	if got := counterByLabel(t, reg, "podtrace_workload_errors_total", "kind"); got["dns"] != 5 {
		t.Errorf("dns errors %v, want the 5 SERVFAIL and REFUSED, not the 20 NXDOMAIN", got["dns"])
	}
}

func TestAGetaddrinfoRowIsTheLookupWithoutPacketCapture(t *testing.T) {
	sink, reg := dnsSink(t, true, false)
	sink.IngestKernel([]kernelagg.Row{
		kernelRow(events.EventDNS, dnsVariant(events.DNSSourceLibc, 1, false), kernelagg.BucketIndex(1_000_000), 6, 6_000_000, 0),
	})
	if got := counterByLabel(t, reg, "podtrace_workload_dns_lookups_total", "rcode"); got["NXDOMAIN"] != 6 {
		t.Errorf("lookups %v, want the 6 calls that found no name", got)
	}
}

func TestEventsCountLookupsByAnswerAndATimeoutHasNoLatency(t *testing.T) {
	sink, reg := dnsSink(t, false, true)
	batch := []*events.Event{
		{Type: events.EventDNS, LatencyNS: 1_000_000, Error: 3},
		{Type: events.EventDNS, LatencyNS: 1_000_000, Error: 2},
		{Type: events.EventDNS, LatencyNS: 5_000_000_000, Error: events.DNSErrorTimeout},
		{Type: events.EventDNS, LatencyNS: 9_000_000, Error: -3, DNSTransport: events.DNSSourceLibc},
		{Type: events.EventDNS, DNSTransport: events.DNSSourceEncrypted},
	}
	for _, e := range batch {
		e.K8s = enriched()
	}
	if err := sink.Export(context.Background(), batch); err != nil {
		t.Fatalf("Export: %v", err)
	}

	want := map[string]float64{"NXDOMAIN": 1, "SERVFAIL": 1, "timeout": 1}
	if got := counterByLabel(t, reg, "podtrace_workload_dns_lookups_total", "rcode"); !sameCounts(got, want) {
		t.Errorf("lookups %v, want %v", got, want)
	}
	if got := dnsLookupCount(t, reg); got != 2 {
		t.Errorf("latency observed %d lookups, want 2: a timeout has no answer time", got)
	}
	if got := counterByLabel(t, reg, "podtrace_workload_errors_total", "kind"); got["dns"] != 2 {
		t.Errorf("dns errors %v, want the SERVFAIL and the timeout", got["dns"])
	}
}

func dnsRows(noerror, nxdomain, servfail uint64) []kernelagg.Row {
	bucket := kernelagg.BucketIndex(1_000_000)
	return []kernelagg.Row{
		kernelRow(events.EventDNS, dnsVariant(events.DNSSourceUDP, 0, false), bucket, noerror, noerror*1_000_000, 0),
		kernelRow(events.EventDNS, dnsVariant(events.DNSSourceUDP, 1, false), bucket, nxdomain, nxdomain*1_000_000, 0),
		kernelRow(events.EventDNS, dnsVariant(events.DNSSourceUDP, 2, true), bucket, servfail, servfail*1_000_000, 0),
	}
}

func TestFailingLookupsRaiseTheDNSFailureIssue(t *testing.T) {
	rows := dnsRows(80, 100, 20)
	active := evaluateOverKernelRows(t, rows, rows)
	if !hasIssue(active, detector.IDDNSFailureRate) {
		t.Fatalf("20 of 200 lookups failed and dns.failure_rate did not fire: %v", active)
	}
	for _, issue := range active {
		if issue.ID == detector.IDDNSFailureRate && !strings.Contains(issue.Message, "10.0% of 200 lookups, mostly SERVFAIL") {
			t.Errorf("message %q", issue.Message)
		}
	}
}

func TestNXDOMAINAnswersDoNotRaiseTheDNSFailureIssue(t *testing.T) {
	rows := dnsRows(20, 180, 0)
	if active := evaluateOverKernelRows(t, rows, rows); hasIssue(active, detector.IDDNSFailureRate) {
		t.Errorf("90%% NXDOMAIN from search-domain expansion raised dns.failure_rate: %v", active)
	}
}
