package export

import (
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

func TestTheExportCountsLookupsByAnswer(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventDNS, LatencyNS: 1_000_000, Target: "a"},
			{Type: events.EventDNS, LatencyNS: 1_000_000, Target: "a.ns.svc", Error: 3},
			{Type: events.EventDNS, LatencyNS: 1_000_000, Target: "b", Error: 2},
			{Type: events.EventDNS, LatencyNS: 5_000_000_000, Target: "c", Error: events.DNSErrorTimeout},
			{Type: events.EventDNS, Target: "1.1.1.1:853", DNSTransport: events.DNSSourceEncrypted},
			{Type: events.EventDNS, Target: "a", Error: -2, DNSTransport: events.DNSSourceLibc},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}
	dns := ExportJSON(d).DNS
	if dns == nil {
		t.Fatal("no DNS data")
	}
	if got := dns["total_lookups"]; got != 4 {
		t.Errorf("total_lookups = %v, want 4: the encrypted connection and the getaddrinfo call are not lookups", got)
	}
	answers, _ := dns["answers"].(map[string]int)
	if answers["NXDOMAIN"] != 1 || answers["SERVFAIL"] != 1 || answers["timeout"] != 1 || len(answers) != 3 {
		t.Errorf("answers = %v", answers)
	}
	if got := dns["answered"]; got != 3 {
		t.Errorf("answered = %v, want the 3 that got an answer", got)
	}
	if got := dns["errors"]; got != 2 {
		t.Errorf("errors = %v, want the SERVFAIL and the timeout", got)
	}
}
