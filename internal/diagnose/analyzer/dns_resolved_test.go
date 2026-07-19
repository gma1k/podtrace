package analyzer

import (
	"testing"

	"github.com/podtrace/podtrace/internal/events"
)

func dnsResp(target, details string) *events.Event {
	return &events.Event{Type: events.EventDNS, Target: target, Details: details}
}

func TestResolvedAddresses_MultiAnswerDedupAndOrder(t *testing.T) {
	responses := []*events.Event{
		dnsResp("example.com", "93.184.216.34, 93.184.216.35"),
		dnsResp("example.com", "93.184.216.34"), // repeat A, must dedup
		dnsResp("api.example.com", "10.0.0.1"),
		dnsResp("cname.example.com", "target.cdn.example."), // CNAME-only: not an IP, dropped
		dnsResp("", "1.1.1.1"),                              // no target, skipped
	}

	got := ResolvedAddresses(responses)

	byName := map[string][]string{}
	for _, ta := range got {
		byName[ta.Target] = ta.Addrs
	}
	if addrs := byName["example.com"]; len(addrs) != 2 ||
		addrs[0] != "93.184.216.34" || addrs[1] != "93.184.216.35" {
		t.Errorf("example.com addrs = %v, want the two distinct A records in order", addrs)
	}
	if addrs := byName["api.example.com"]; len(addrs) != 1 || addrs[0] != "10.0.0.1" {
		t.Errorf("api.example.com addrs = %v, want [10.0.0.1]", addrs)
	}
	if _, present := byName["cname.example.com"]; present {
		t.Error("CNAME-only target must not appear in resolved addresses")
	}
	if _, present := byName[""]; present {
		t.Error("empty target must be skipped")
	}

	// Sorted by fan-out: example.com (2 addrs) before api.example.com (1).
	if len(got) != 2 || got[0].Target != "example.com" {
		t.Errorf("ordering = %+v, want example.com first (highest fan-out)", got)
	}
}

func TestResolvedAddresses_Empty(t *testing.T) {
	if got := ResolvedAddresses(nil); len(got) != 0 {
		t.Errorf("ResolvedAddresses(nil) = %v, want empty", got)
	}
}
