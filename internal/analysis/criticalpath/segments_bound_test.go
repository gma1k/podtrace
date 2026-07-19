package criticalpath

import (
	"testing"
	"time"
)

func TestFeed_SegmentsBoundedPerWindow(t *testing.T) {
	a := New(time.Hour, nil)
	const pid = 42
	const fed = maxSegmentsPerWindow + 500
	for i := 0; i < fed; i++ {
		a.Feed(nonBoundaryEvent(pid))
	}

	a.mu.Lock()
	w := a.windows[pid]
	a.mu.Unlock()
	if w == nil {
		t.Fatal("expected a window for the fed PID")
	}
	if len(w.segments) > maxSegmentsPerWindow {
		t.Errorf("window segments = %d, want <= %d", len(w.segments), maxSegmentsPerWindow)
	}

	var total uint64
	for _, s := range w.segments {
		total += s.LatencyNS
	}
	if want := uint64(fed) * 1_000_000; total != want {
		t.Errorf("summed segment latency = %d, want %d (overflow fold lost latency)", total, want)
	}
}
