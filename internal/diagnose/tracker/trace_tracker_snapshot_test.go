package tracker

import (
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/clock"
	"github.com/podtrace/podtrace/internal/events"
)

func snapshotEvent(traceID, spanID string) *events.Event {
	return &events.Event{
		TraceID:   traceID,
		SpanID:    spanID,
		Type:      events.EventHTTPReq,
		Timestamp: clock.WallToBPFTimestamp(time.Now()),
	}
}

// TestSnapshotForExport_ExactlyOnce is a regression test for the duplicate
// re-export bug: every accumulated trace used to be pushed to every exporter
// on every 5s tick, with nothing marking spans as exported.
func TestSnapshotForExport_ExactlyOnce(t *testing.T) {
	tt := NewTraceTracker()
	tt.ProcessEvent(snapshotEvent("t1", "s1"), nil)

	first := tt.SnapshotForExport(time.Hour, true)
	if len(first) != 1 || len(first[0].Spans) != 1 {
		t.Fatalf("first snapshot = %d traces, want 1 trace with 1 span", len(first))
	}

	if second := tt.SnapshotForExport(time.Hour, true); len(second) != 0 {
		t.Fatalf("second snapshot = %d traces, want 0 (spans must export exactly once)", len(second))
	}

	tt.ProcessEvent(snapshotEvent("t1", "s2"), nil)
	third := tt.SnapshotForExport(time.Hour, true)
	if len(third) != 1 || len(third[0].Spans) != 1 || third[0].Spans[0].SpanID != "s2" {
		t.Fatalf("third snapshot must carry only the new span s2, got %+v", third)
	}
}

// TestSnapshotForExport_SettleWindow: traces still receiving events are
// skipped until idle for the settle interval, unless force (shutdown flush).
func TestSnapshotForExport_SettleWindow(t *testing.T) {
	tt := NewTraceTracker()
	tt.ProcessEvent(snapshotEvent("t1", "s1"), nil)

	if got := tt.SnapshotForExport(time.Hour, false); len(got) != 0 {
		t.Fatalf("just-updated trace must settle before export, got %d traces", len(got))
	}
	if got := tt.SnapshotForExport(time.Hour, true); len(got) != 1 {
		t.Fatalf("force must flush settling traces, got %d traces", len(got))
	}
}

// TestSnapshotAll_DeepCopyAndNoWatermark: graph/report consumers get deep
// copies (mutating them must not touch live state — exporters used to sort
// and mutate live spans, racing ProcessEvent) and do not consume the export
// watermark.
func TestSnapshotAll_DeepCopyAndNoWatermark(t *testing.T) {
	tt := NewTraceTracker()
	ev := snapshotEvent("t1", "s1")
	ev.Target = "10.0.0.1:443"
	tt.ProcessEvent(ev, nil)

	snap := tt.SnapshotAll()
	if len(snap) != 1 || len(snap[0].Spans) != 1 {
		t.Fatalf("SnapshotAll = %+v, want 1 trace with 1 span", snap)
	}
	snap[0].Spans[0].Attributes["target"] = "mutated"
	snap[0].Spans[0].Events = nil

	live := tt.GetTrace("t1")
	live.mu.RLock()
	if live.Spans[0].Attributes["target"] != "10.0.0.1:443" {
		t.Error("mutating a snapshot leaked into the live trace")
	}
	if len(live.Spans[0].Events) != 1 {
		t.Error("snapshot shares the live Events slice header")
	}
	live.mu.RUnlock()

	if got := tt.SnapshotForExport(time.Hour, true); len(got) != 1 {
		t.Errorf("SnapshotAll must not consume the export watermark, export snapshot = %d traces", len(got))
	}
}