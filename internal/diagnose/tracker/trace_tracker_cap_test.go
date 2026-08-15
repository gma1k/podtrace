package tracker

import (
	"fmt"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/clock"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
)

func TestProcessEvent_CapsTrackedTraces(t *testing.T) {
	tt := NewTraceTracker()
	now := clock.WallToBPFTimestamp(time.Now())
	for i := 0; i < config.MaxTrackedTraces+500; i++ {
		tt.ProcessEvent(&events.Event{
			TraceID:   fmt.Sprintf("%032x", i),
			SpanID:    "s",
			Timestamp: now,
			Type:      events.EventHTTPReq,
		}, nil)
	}
	if got := tt.GetTraceCount(); got != config.MaxTrackedTraces {
		t.Fatalf("tracked traces = %d, want exactly the cap %d (a flood of distinct trace IDs must not grow the map)", got, config.MaxTrackedTraces)
	}
}

func TestProcessEvent_CapsSpansPerTrace(t *testing.T) {
	tt := NewTraceTracker()
	now := clock.WallToBPFTimestamp(time.Now())
	for i := 0; i < config.MaxSpansPerTrace+50; i++ {
		tt.ProcessEvent(&events.Event{
			TraceID:   "one-trace",
			SpanID:    fmt.Sprintf("%016x", i),
			Timestamp: now,
			Type:      events.EventHTTPReq,
		}, nil)
	}
	tr := tt.GetTrace("one-trace")
	if tr == nil {
		t.Fatal("trace missing after span flood")
	}
	if got := len(tr.Spans); got != config.MaxSpansPerTrace {
		t.Fatalf("spans = %d, want exactly the cap %d (a span-ID flood under one trace must not grow unbounded)", got, config.MaxSpansPerTrace)
	}
}

func TestCleanupOldTraces_KeepsRecentlyUpdated(t *testing.T) {
	tt := NewTraceTracker()
	tt.ProcessEvent(&events.Event{
		TraceID:   "fresh",
		SpanID:    "s",
		Timestamp: clock.WallToBPFTimestamp(time.Now()),
		Type:      events.EventHTTPReq,
	}, nil)

	tt.CleanupOldTraces(1 * time.Minute)

	if tt.GetTraceCount() != 1 {
		t.Fatalf("recently-updated trace was evicted; count = %d, want 1", tt.GetTraceCount())
	}
}
