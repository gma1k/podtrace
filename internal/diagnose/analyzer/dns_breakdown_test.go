package analyzer

import (
	"testing"

	"github.com/podtrace/podtrace/internal/events"
)

func TestDNSRCodeBreakdown(t *testing.T) {
	responses := []*events.Event{
		{Type: events.EventDNS, Error: 3}, // NXDOMAIN
		{Type: events.EventDNS, Error: 3}, // NXDOMAIN
		{Type: events.EventDNS, Error: 2}, // SERVFAIL
		{Type: events.EventDNS, Error: 0}, // NOERROR (excluded)
		nil,
	}
	got := DNSRCodeBreakdown(responses)
	if len(got) != 2 ||
		got[0].Target != "NXDOMAIN" || got[0].Count != 2 ||
		got[1].Target != "SERVFAIL" || got[1].Count != 1 {
		t.Fatalf("DNSRCodeBreakdown = %+v", got)
	}
}

func TestDNSQueryTypeBreakdown(t *testing.T) {
	responses := []*events.Event{
		{Type: events.EventDNS, TCPState: 1},  // A
		{Type: events.EventDNS, TCPState: 1},  // A
		{Type: events.EventDNS, TCPState: 28}, // AAAA
		nil,
	}
	got := DNSQueryTypeBreakdown(responses)
	if len(got) != 2 ||
		got[0].Target != "A" || got[0].Count != 2 ||
		got[1].Target != "AAAA" || got[1].Count != 1 {
		t.Fatalf("DNSQueryTypeBreakdown = %+v", got)
	}
}
