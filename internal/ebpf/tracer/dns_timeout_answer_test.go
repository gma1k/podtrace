package tracer

import (
	"testing"

	"github.com/gma1k/podtrace/internal/ebpf/filter"
	"github.com/gma1k/podtrace/internal/events"
)

func TestATimedOutQueryIsAFailedLookupWithItsServer(t *testing.T) {
	tr := newAttributionTestTracer()
	tr.filter = filter.NewCgroupFilter()
	val := dnsQueryState{TsNS: 1, LastNS: 2, QType: 1, ServerIP: 0x0a00600a, Transport: 1}
	copy(val.Name[:], "kubernetes.default")

	ev := tr.buildDNSTimeoutEvent(dnsFlowKey{CgroupID: 5, Txid: 9}, val, 6_000_000_001, 6_000_000_000)
	if ev == nil {
		t.Fatal("no event for a query that got no answer")
	}
	if ev.DNSAnswer() != events.DNSAnswerTimeout || !ev.IsError() {
		t.Errorf("answer %q error %v: a timeout looked like an answered lookup", ev.DNSAnswer(), ev.IsError())
	}
	if ev.DNSServerIP != val.ServerIP || ev.DNSTransport != val.Transport || !ev.CountsAsDNSLookup(true) {
		t.Errorf("server %x transport %d: the timeout lost the query's server", ev.DNSServerIP, ev.DNSTransport)
	}
	if ev.LatencyNS != 6_000_000_000 {
		t.Errorf("latency %d, want the whole wait since the first send", ev.LatencyNS)
	}
}
