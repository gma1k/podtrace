package tracker

import (
	"testing"
	"time"
)

func TestSnapshotForExport_WatermarkIsPerExporter(t *testing.T) {
	tt := NewTraceTracker()
	tt.ProcessEvent(snapshotEvent("t1", "s1"), nil)

	if got := tt.SnapshotForExport(time.Hour, true, "a"); len(got) != 1 {
		t.Fatalf("exporter a first snapshot = %d traces, want 1", len(got))
	}
	if got := tt.SnapshotForExport(time.Hour, true, "b"); len(got) != 1 {
		t.Fatalf("exporter b first snapshot = %d traces, want 1", len(got))
	}

	tt.CommitExport([]*Trace{{TraceID: "t1", Spans: []*Span{{SpanID: "s1"}}}}, "a")

	if got := tt.SnapshotForExport(time.Hour, true, "a"); len(got) != 0 {
		t.Fatalf("exporter a re-export after commit = %d traces, want 0", len(got))
	}
	if got := tt.SnapshotForExport(time.Hour, true, "b"); len(got) != 1 {
		t.Fatalf("exporter b snapshot = %d traces, want 1; a's commit must not advance b's watermark", len(got))
	}
}

func TestCommitExport_InitializesNilWatermarkMap(t *testing.T) {
	tt := NewTraceTracker()
	tt.traces["t1"] = &Trace{TraceID: "t1", Spans: []*Span{{SpanID: "s1"}}}

	tt.CommitExport([]*Trace{{TraceID: "t1", Spans: []*Span{{SpanID: "s1"}}}}, "a")

	if got := tt.SnapshotForExport(time.Hour, true, "a"); len(got) != 0 {
		t.Fatalf("committing against a trace with no watermark map must still record it; re-export = %d", len(got))
	}
}

func TestCommitExport_AdvancesOnlyNamedExporter(t *testing.T) {
	tt := NewTraceTracker()
	tt.ProcessEvent(snapshotEvent("t1", "s1"), nil)
	tt.ProcessEvent(snapshotEvent("t1", "s2"), nil)

	tt.CommitExport([]*Trace{{TraceID: "t1", Spans: []*Span{{SpanID: "s1"}}}}, "a")

	gotA := tt.SnapshotForExport(time.Hour, true, "a")
	if len(gotA) != 1 || len(gotA[0].Spans) != 1 || gotA[0].Spans[0].SpanID != "s2" {
		t.Fatalf("exporter a must only see the uncommitted span s2, got %+v", gotA)
	}
	gotB := tt.SnapshotForExport(time.Hour, true, "b")
	if len(gotB) != 1 || len(gotB[0].Spans) != 2 {
		t.Fatalf("exporter b must still see both spans, got %+v", gotB)
	}
}
