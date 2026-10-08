package analyzer

import (
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestANameThatDoesNotExistIsNotADNSError(t *testing.T) {
	responses := []*events.Event{
		{Type: events.EventDNS, Target: "a.svc.cluster.local", LatencyNS: 1_000_000, Error: 3},
		{Type: events.EventDNS, Target: "a", LatencyNS: 1_000_000},
	}
	if _, _, errors, _, _, _, _ := AnalyzeDNS(nil, responses); errors != 0 {
		t.Errorf("errors = %d, want 0: search-domain expansion answers NXDOMAIN on every lookup", errors)
	}
}

func TestATimedOutLookupIsAnErrorWithoutALatency(t *testing.T) {
	responses := []*events.Event{
		{Type: events.EventDNS, Target: "a", LatencyNS: 2_000_000},
		{Type: events.EventDNS, Target: "b", LatencyNS: 5_000_000_000, Error: events.DNSErrorTimeout},
	}
	avg, maxLatency, errors, _, _, _, _ := AnalyzeDNS(nil, responses)
	if errors != 1 {
		t.Errorf("errors = %d, want the timeout", errors)
	}
	if avg != 2 || maxLatency != 2 {
		t.Errorf("avg %v max %v, want 2ms each: a timeout has no answer time", avg, maxLatency)
	}
}

func TestTheAnswerBreakdownNamesEveryAnswerButNOERROR(t *testing.T) {
	responses := []*events.Event{
		{Type: events.EventDNS},
		{Type: events.EventDNS, Error: 3},
		{Type: events.EventDNS, Error: 3},
		{Type: events.EventDNS, Error: 2},
		{Type: events.EventDNS, Error: events.DNSErrorTimeout},
		{Type: events.EventDNS, Error: -3, DNSTransport: events.DNSSourceLibc},
	}
	got := map[string]int{}
	for _, a := range DNSRCodeBreakdown(responses) {
		got[a.Target] = a.Count
	}
	want := map[string]int{"NXDOMAIN": 2, "SERVFAIL": 2, "timeout": 1}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %d, want %d (all %v)", k, got[k], v, got)
		}
	}
}

func TestOnlyLookupsAreCountedAsLookups(t *testing.T) {
	evs := []*events.Event{
		{Type: events.EventDNS, DNSTransport: events.DNSSourceUDP},
		{Type: events.EventDNS, DNSTransport: events.DNSSourceTCP},
		{Type: events.EventDNS, DNSTransport: events.DNSSourceEncrypted},
		{Type: events.EventDNS, DNSTransport: events.DNSSourceLibc},
		nil,
	}
	if got := len(DNSLookups(evs, true)); got != 2 {
		t.Errorf("with packet capture %d lookups, want the 2 read off the wire", got)
	}
	if got := len(DNSLookups(evs, false)); got != 3 {
		t.Errorf("without packet capture %d lookups, want the wire's 2 and the getaddrinfo call", got)
	}
}
