package tracker

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/clock"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/safeconv"
)

func withTraceBudget(t *testing.T, bytes int64) {
	t.Helper()
	orig := config.MaxTrackedTraceBytes
	config.MaxTrackedTraceBytes = bytes
	t.Cleanup(func() { config.MaxTrackedTraceBytes = orig })
}

func spanEvent(trace, span int, details string) *events.Event {
	return &events.Event{
		Type:        events.EventHTTPReq,
		TraceID:     fmt.Sprintf("%032x", trace),
		SpanID:      fmt.Sprintf("%016x", span),
		Details:     details + fmt.Sprint(span),
		Target:      "/x",
		ProcessName: "app",
		Timestamp:   clock.WallToBPFTimestamp(time.Now()),
	}
}

func heldBytes(tt *TraceTracker) (sum int64) {
	for _, tr := range tt.traces {
		sum += tr.bytes
	}
	return sum
}

func TestClientChosenTraceIDsCannotGrowTheTrackerPastItsByteBudget(t *testing.T) {
	const budget = 8 << 20
	withTraceBudget(t, budget)
	details := strings.Repeat("x", 512)

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	tt := NewTraceTracker()
	for tr := range 200 {
		for s := range 1000 {
			tt.ProcessEvent(spanEvent(tr, s, details), nil)
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)

	if tt.bytes > budget || tt.bytes != heldBytes(tt) {
		t.Errorf("accounted %d bytes (traces hold %d), budget %d", tt.bytes, heldBytes(tt), budget)
	}
	retained := safeconv.Uint64ToInt64(after.HeapAlloc) - safeconv.Uint64ToInt64(before.HeapAlloc)
	if retained > 2*budget {
		t.Errorf("retained %d MiB against an %d MiB budget; the estimate undercounts a span", retained>>20, budget>>20)
	}
	if tt.EvictedTraceCount() == 0 || tt.GetTrace(fmt.Sprintf("%032x", 199)) == nil {
		t.Errorf("evicted %d traces and lost the newest; the budget must be met by evicting the idlest",
			tt.EvictedTraceCount())
	}
	runtime.KeepAlive(tt)
}

func TestATraceThatAloneFillsTheBudgetKeepsItsTimingButNotMoreEvents(t *testing.T) {
	withTraceBudget(t, 4<<10)
	tt := NewTraceTracker()
	for s := range 50 {
		tt.ProcessEvent(spanEvent(1, s%2, strings.Repeat("y", 256)), nil)
	}
	tr := tt.GetTrace(fmt.Sprintf("%032x", 1))
	if tr == nil || len(tr.Spans) == 0 {
		t.Fatal("the trace was not tracked at all")
	}
	if tt.bytes > 4<<10 {
		t.Errorf("accounted %d bytes over a %d byte budget", tt.bytes, 4<<10)
	}
	var kept, dropped int
	for _, s := range tr.Spans {
		kept += len(s.Events)
		dropped += s.droppedEvents
	}
	if dropped == 0 || kept+dropped != 25*len(tr.Spans) {
		t.Errorf("kept %d and dropped %d of 50 events", kept, dropped)
	}
	if tr.Spans[0].Attributes["podtrace.dropped_events"] == "" {
		t.Error("the span does not say it dropped events")
	}
}

func TestAZeroByteBudgetTracksNothing(t *testing.T) {
	withTraceBudget(t, 0)
	tt := NewTraceTracker()
	tt.ProcessEvent(spanEvent(1, 1, ""), nil)
	if tr := tt.GetTrace(fmt.Sprintf("%032x", 1)); tr != nil && len(tr.Spans) != 0 {
		t.Errorf("tracked %d spans with no budget", len(tr.Spans))
	}
}

func TestRemovingTracesReturnsTheirBytes(t *testing.T) {
	tt := NewTraceTracker()
	for tr := range 5 {
		tt.ProcessEvent(spanEvent(tr, 1, "z"), nil)
	}
	if tt.bytes == 0 {
		t.Fatal("nothing was accounted")
	}
	tt.CleanupOldTraces(-time.Second)
	if tt.GetTraceCount() != 0 || tt.bytes != 0 {
		t.Errorf("%d traces and %d bytes left after removing every trace", tt.GetTraceCount(), tt.bytes)
	}
}

func TestEventsRacingTheCleanupAreNeverChargedToAForgottenTrace(t *testing.T) {
	tt := NewTraceTracker()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				tt.CleanupOldTraces(-time.Second)
			}
		}
	}()
	for i := range 20_000 {
		tt.ProcessEvent(spanEvent(i%3, i%7, "r"), nil)
	}
	close(stop)
	wg.Wait()
	tt.mu.Lock()
	defer tt.mu.Unlock()
	if tt.bytes != heldBytes(tt) {
		t.Errorf("tracker accounts %d bytes but its traces hold %d: an event landed on a trace already forgotten",
			tt.bytes, heldBytes(tt))
	}
}
