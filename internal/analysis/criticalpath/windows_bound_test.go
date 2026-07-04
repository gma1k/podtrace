package criticalpath

import (
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

func nonBoundaryEvent(pid uint32) *events.Event {
	return &events.Event{Type: events.EventDBQuery, PID: pid, LatencyNS: 1_000_000, Details: "SELECT"}
}

func TestFeed_WindowMapBounded(t *testing.T) {
	a := New(time.Minute, nil)
	for pid := uint32(1); pid <= maxWindows+500; pid++ {
		a.Feed(nonBoundaryEvent(pid))
	}
	a.mu.Lock()
	n := len(a.windows)
	a.mu.Unlock()
	if n > maxWindows {
		t.Fatalf("windows map grew to %d, cap is %d", n, maxWindows)
	}
}

func TestFeed_BoundaryStillEmitsWhenFull(t *testing.T) {
	var emitted []CriticalPath
	a := New(time.Minute, func(cp CriticalPath) { emitted = append(emitted, cp) })
	for pid := uint32(1); pid <= maxWindows; pid++ {
		a.Feed(nonBoundaryEvent(pid))
	}
	a.Feed(&events.Event{Type: events.EventHTTPResp, PID: maxWindows + 1, LatencyNS: 2_000_000})
	if len(emitted) != 1 {
		t.Fatalf("boundary at capacity emitted %d paths, want 1", len(emitted))
	}
	a.mu.Lock()
	n := len(a.windows)
	a.mu.Unlock()
	if n > maxWindows {
		t.Fatalf("windows map grew to %d after boundary, cap is %d", n, maxWindows)
	}
}

func TestEvict_FreesRoomForNewWindows(t *testing.T) {
	a := New(time.Millisecond, nil)
	for pid := uint32(1); pid <= maxWindows; pid++ {
		a.Feed(nonBoundaryEvent(pid))
	}
	time.Sleep(5 * time.Millisecond)
	a.Evict()

	a.Feed(nonBoundaryEvent(maxWindows + 1))
	a.mu.Lock()
	_, ok := a.windows[maxWindows+1]
	a.mu.Unlock()
	if !ok {
		t.Fatal("post-eviction feed did not create a window")
	}
}
