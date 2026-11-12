package tracker

import (
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

func TestCommittingAPrefixAdvancesTheWatermarkOnlyPastIt(t *testing.T) {
	tt := NewTraceTracker()
	for _, id := range []string{"0000000000000001", "0000000000000002", "0000000000000003"} {
		tt.ProcessEvent(&events.Event{Type: events.EventDNS, TraceID: "aabbccddeeff00112233445566778899", SpanID: id}, nil)
	}
	snap := tt.SnapshotForExport(time.Hour, true, "splunk")
	if len(snap) != 1 || len(snap[0].Spans) != 3 {
		t.Fatalf("snapshot = %d traces, want 1 with 3 spans", len(snap))
	}

	tt.CommitExport([]*Trace{snap[0].Prefix(2)}, "splunk")

	rest := tt.SnapshotForExport(time.Hour, true, "splunk")
	if len(rest) != 1 || len(rest[0].Spans) != 1 || rest[0].Spans[0].SpanID != "0000000000000003" {
		t.Fatalf("after committing 2 of 3 spans the next export offers %+v, want only the third span", rest)
	}
}

func TestPrefixClampsItsLength(t *testing.T) {
	tr := &Trace{TraceID: "t", Spans: []*Span{{SpanID: "a"}, {SpanID: "b"}}}
	if got := len(tr.Prefix(5).Spans); got != 2 {
		t.Errorf("Prefix(5) of 2 spans has %d spans", got)
	}
	if got := len(tr.Prefix(-1).Spans); got != 0 {
		t.Errorf("Prefix(-1) has %d spans", got)
	}
	p := tr.Prefix(1)
	p.Spans = append(p.Spans, &Span{SpanID: "x"})
	if tr.Spans[1].SpanID != "b" {
		t.Error("appending to a prefix overwrote the snapshot's spans")
	}
}
