package exporter

import (
	"testing"

	"github.com/podtrace/podtrace/internal/diagnose/tracker"
	"github.com/podtrace/podtrace/internal/events"
)

func spanWithEvent(t events.EventType) *tracker.Span {
	return &tracker.Span{
		Events: []*events.Event{{Type: t}},
	}
}

func TestSpanType_AllBranches(t *testing.T) {
	cases := []struct {
		name string
		span *tracker.Span
		want string
	}{
		{"http", spanWithEvent(events.EventHTTPReq), "web"},
		{"db", spanWithEvent(events.EventDBQuery), "db"},
		{"grpc", spanWithEvent(events.EventGRPCMethod), "rpc"},
		{"default unmatched", spanWithEvent(events.EventConnect), "custom"},
		{"no events", &tracker.Span{Events: nil}, "custom"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := spanType(tc.span); got != tc.want {
				t.Errorf("spanType(%s) = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

// TestSpanType_FirstMatchWins confirms the function returns on the first
// classifiable event in the slice rather than the last.
func TestSpanType_FirstMatchWins(t *testing.T) {
	span := &tracker.Span{
		Events: []*events.Event{
			{Type: events.EventHTTPReq},
			{Type: events.EventDBQuery},
		},
	}
	if got := spanType(span); got != "web" {
		t.Errorf("spanType() = %q, want %q (first match)", got, "web")
	}
}
