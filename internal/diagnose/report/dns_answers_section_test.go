package report

import (
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

func TestTheDNSSectionCountsLookupsNotConnectionsAndNamesEachAnswer(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, LatencyNS: 2_000_000, Target: "a"},
			{Type: events.EventDNS, LatencyNS: 1_000_000, Target: "a.ns.svc", Error: 3},
			{Type: events.EventDNS, LatencyNS: 1_000_000, Target: "b", Error: 2},
			{Type: events.EventDNS, LatencyNS: 5_000_000_000, Target: "c", Error: events.DNSErrorTimeout},
			{Type: events.EventDNS, Target: "1.1.1.1:853", DNSTransport: events.DNSSourceEncrypted},
			{Type: events.EventDNS, Target: "a", Error: -2, DNSTransport: events.DNSSourceLibc},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}
	got := GenerateDNSSection(d, time.Second)
	for _, want := range []string{"Total lookups: 4", "Errors: 2 (50.0%)", "Max latency: 2.00ms", "- NXDOMAIN: 1", "- SERVFAIL: 1", "- timeout: 1"} {
		if !strings.Contains(got, want) {
			t.Errorf("section lacks %q:\n%s", want, got)
		}
	}
	if !strings.Contains(got, "Encrypted resolver connections") || !strings.Contains(got, "- 1.1.1.1:853: 1") {
		t.Errorf("the encrypted resolver connection is not listed as one:\n%s", got)
	}
	if strings.Count(got, "853") != 1 {
		t.Errorf("the encrypted resolver connection was also listed as a lookup:\n%s", got)
	}
}

func TestTheDNSSectionSaysSoWhenNoLookupWasAnswered(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, LatencyNS: 5_000_000_000, Target: "c", Error: events.DNSErrorTimeout},
			{Type: events.EventDNS, LatencyNS: 5_000_000_000, Target: "c", Error: events.DNSErrorTimeout},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}
	got := GenerateDNSSection(d, time.Second)
	if !strings.Contains(got, "No lookup was answered") || strings.Contains(got, "Average latency") {
		t.Errorf("every lookup timed out and the section shows a latency:\n%s", got)
	}
}

func TestAWorkloadThatOnlyUsesEncryptedDNSStillGetsADNSSection(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, Target: "1.1.1.1:853", DNSTransport: events.DNSSourceEncrypted},
			{Type: events.EventDNS, Target: "1.1.1.1:853", DNSTransport: events.DNSSourceEncrypted},
			{Type: events.EventDNS, Target: "8.8.8.8:443", DNSTransport: events.DNSSourceEncrypted},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}
	got := GenerateDNSSection(d, time.Second)
	if !strings.Contains(got, "- 1.1.1.1:853: 2") || !strings.Contains(got, "- 8.8.8.8:443: 1") {
		t.Errorf("the encrypted resolvers are missing:\n%s", got)
	}
	if strings.Contains(got, "Total lookups") || strings.Contains(got, "Errors") {
		t.Errorf("encrypted connections were reported as lookups:\n%s", got)
	}
}
