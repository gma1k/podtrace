package stacktrace

import (
	"context"
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

const kernelFrame = 0xffffffff81000000

func TestAHotStackReportsTheMeanLatencyOfItsEvents(t *testing.T) {
	d := &mockDiagnostician{events: []*events.Event{
		{Type: events.EventDNS, LatencyNS: 10_000_000, Stack: []uint64{kernelFrame}},
		{Type: events.EventDNS, LatencyNS: 30_000_000, Stack: []uint64{kernelFrame}},
	}}
	got := GenerateStackTraceSectionWithContext(d, context.Background())
	if !strings.Contains(got, "2 events") || !strings.Contains(got, "avg latency=20.00ms") {
		t.Errorf("section = %q, want 2 events at avg latency=20.00ms", got)
	}
}

func TestHotStacksWithEqualCountsAreOrderedByTotalLatency(t *testing.T) {
	d := &mockDiagnostician{events: []*events.Event{
		{Type: events.EventDNS, LatencyNS: 10_000_000, Stack: []uint64{kernelFrame}},
		{Type: events.EventConnect, LatencyNS: 50_000_000, Stack: []uint64{kernelFrame}},
		{Type: events.EventDNS, LatencyNS: 30_000_000, Stack: []uint64{kernelFrame}},
		{Type: events.EventConnect, LatencyNS: 50_000_000, Stack: []uint64{kernelFrame}},
	}}
	for i := 0; i < 20; i++ {
		got := GenerateStackTraceSectionWithContext(d, context.Background())
		slow := strings.Index(got, "avg latency=50.00ms")
		fast := strings.Index(got, "avg latency=20.00ms")
		if slow < 0 || fast < 0 || slow > fast {
			t.Fatalf("section = %q, want the 50ms stack before the 20ms one", got)
		}
	}
}

func TestHotStacksWithEqualCountsAndLatencyAreOrderedByKey(t *testing.T) {
	d := &mockDiagnostician{events: []*events.Event{
		{Type: events.EventConnect, LatencyNS: 10_000_000, Stack: []uint64{kernelFrame}},
		{Type: events.EventDNS, LatencyNS: 10_000_000, Stack: []uint64{kernelFrame}},
	}}
	first := GenerateStackTraceSectionWithContext(d, context.Background())
	for i := 0; i < 20; i++ {
		if got := GenerateStackTraceSectionWithContext(d, context.Background()); got != first {
			t.Fatalf("section changed between runs:\n%s\n---\n%s", first, got)
		}
	}
}

func TestAStackSummaryWithNoEventsHasNoLatency(t *testing.T) {
	if got := (&stackSummary{}).avgLatencyMs(); got != 0 {
		t.Errorf("avgLatencyMs = %v, want 0", got)
	}
}
