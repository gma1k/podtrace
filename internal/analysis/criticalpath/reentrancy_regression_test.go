package criticalpath_test

import (
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/analysis/criticalpath"
	"github.com/podtrace/podtrace/internal/events"
)

// TestEmit_ReentrantCallbackDoesNotDeadlock: the emit callback used to run
// under the analyzer's mutex, so a callback that fed an event back in (or
// merely blocked) deadlocked the event hot path. It must run lock-free.
func TestEmit_ReentrantCallbackDoesNotDeadlock(t *testing.T) {
	var a *criticalpath.Analyzer
	emitted := 0
	a = criticalpath.New(time.Second, func(cp criticalpath.CriticalPath) {
		emitted++
		if emitted == 1 {
			a.Feed(&events.Event{Type: events.EventHTTPResp, PID: 999, LatencyNS: 1})
		}
	})

	done := make(chan struct{})
	go func() {
		a.Feed(&events.Event{Type: events.EventHTTPResp, PID: 1, LatencyNS: 1_000_000})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("re-entrant emit callback deadlocked the analyzer")
	}
	if emitted != 2 {
		t.Errorf("emitted = %d, want 2 (outer + re-entrant)", emitted)
	}
}
