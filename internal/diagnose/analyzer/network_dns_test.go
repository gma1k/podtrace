package analyzer

import (
	"testing"

	"github.com/podtrace/podtrace/internal/events"
)

// A connect to an IP that podtrace resolved from a name (carried in Details)
// must surface "ip:port (name)" in the connection target list.
func TestAnalyzeConnections_DNSCorrelationLabel(t *testing.T) {
	evs := []*events.Event{
		{Type: events.EventConnect, Target: "93.184.216.34:443", Details: "example.com", LatencyNS: 1_000_000},
		{Type: events.EventConnect, Target: "10.0.0.5:80", LatencyNS: 1_000_000}, // no correlation
	}
	_, _, _, _, _, _, topTargets, _ := AnalyzeConnections(evs)

	var foundCorrelated, foundPlain bool
	for _, tt := range topTargets {
		if tt.Target == "93.184.216.34:443 (example.com)" {
			foundCorrelated = true
		}
		if tt.Target == "10.0.0.5:80" {
			foundPlain = true
		}
	}
	if !foundCorrelated {
		t.Errorf("expected correlated label '93.184.216.34:443 (example.com)', got %+v", topTargets)
	}
	if !foundPlain {
		t.Errorf("expected uncorrelated target '10.0.0.5:80' unchanged, got %+v", topTargets)
	}
}

// AnalyzeDNS: names/counts come from queries; latency + errors come from responses.
func TestAnalyzeDNS_QueryResponseSplit(t *testing.T) {
	queries := []*events.Event{
		{Type: events.EventDNSQuery, Target: "example.com"},
		{Type: events.EventDNSQuery, Target: "example.com"},
		{Type: events.EventDNSQuery, Target: "nope.invalid"},
	}
	responses := []*events.Event{
		{Type: events.EventDNS, Target: "example.com", LatencyNS: 2_000_000, Error: 0},
		{Type: events.EventDNS, Target: "nope.invalid", LatencyNS: 1_000_000, Error: 3}, // NXDOMAIN
	}
	avg, _, errors, _, _, _, topTargets := AnalyzeDNS(queries, responses)

	if errors != 1 {
		t.Errorf("errors = %d, want 1 (one NXDOMAIN response)", errors)
	}
	if avg <= 0 {
		t.Errorf("avg latency should be >0 from responses, got %v", avg)
	}
	// example.com appears twice in queries -> count 2 (names come from queries).
	var exampleCount int
	for _, tt := range topTargets {
		if tt.Target == "example.com" {
			exampleCount = tt.Count
		}
	}
	if exampleCount != 2 {
		t.Errorf("example.com lookup count = %d, want 2 (from queries)", exampleCount)
	}
}
