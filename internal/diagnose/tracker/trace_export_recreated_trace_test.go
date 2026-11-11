package tracker

import (
	"testing"
	"time"
)

func TestAnExportOfAnEvictedTraceIsNotCommittedToItsSuccessor(t *testing.T) {
	tt := NewTraceTracker()
	tt.ProcessEvent(snapshotEvent("t1", "s1"), nil)
	tt.ProcessEvent(snapshotEvent("t1", "s2"), nil)

	inFlight := tt.SnapshotForExport(time.Hour, true, "otlp")
	if len(inFlight) != 1 || len(inFlight[0].Spans) != 2 {
		t.Fatalf("snapshot = %+v, want t1 with two spans", inFlight)
	}

	tt.CleanupOldTraces(-time.Second)
	tt.ProcessEvent(snapshotEvent("t1", "n1"), nil)
	tt.ProcessEvent(snapshotEvent("t1", "n2"), nil)

	tt.CommitExport(inFlight, "otlp")

	next := tt.SnapshotForExport(time.Hour, true, "otlp")
	if len(next) != 1 || len(next[0].Spans) != 2 || next[0].Spans[0].SpanID != "n1" {
		t.Fatalf("snapshot after commit = %+v, want the new trace's spans n1 and n2 still to export", next)
	}
}

func TestAnExportIsCommittedToTheTraceItWasTakenFrom(t *testing.T) {
	tt := NewTraceTracker()
	tt.ProcessEvent(snapshotEvent("t1", "s1"), nil)

	tt.CommitExport(tt.SnapshotForExport(time.Hour, true, "otlp"), "otlp")

	if got := tt.SnapshotForExport(time.Hour, true, "otlp"); len(got) != 0 {
		t.Fatalf("re-export after commit = %+v, want nothing", got)
	}
}
