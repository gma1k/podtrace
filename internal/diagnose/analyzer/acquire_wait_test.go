package analyzer

import (
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

func acquireWait(ms int) *events.Event {
	return &events.Event{
		Type:      events.EventDBAcquire,
		LatencyNS: uint64(ms) * 1_000_000,
	}
}

func TestAcquireWaitsSummariseBlockingAcquisitions(t *testing.T) {
	got := AnalyzeAcquireWaits([]*events.Event{
		acquireWait(100), acquireWait(200), acquireWait(300), acquireWait(400),
	})

	if got.Count != 4 {
		t.Errorf("Count = %d, want 4", got.Count)
	}
	if got.Total != time.Second {
		t.Errorf("Total = %v, want 1s", got.Total)
	}
	if got.Avg != 250*time.Millisecond {
		t.Errorf("Avg = %v, want 250ms", got.Avg)
	}
	if got.Max != 400*time.Millisecond {
		t.Errorf("Max = %v, want 400ms", got.Max)
	}
}

func TestAcquireWaitsAreEmptyWhenNothingBlocked(t *testing.T) {
	got := AnalyzeAcquireWaits(nil)

	if got.Count != 0 || got.Total != 0 || got.Avg != 0 || got.Max != 0 {
		t.Errorf("got %+v, want a zero summary.\n\nThe probe records only acquisitions "+
			"that blocked, so a healthy pool contributes no samples; dividing by a zero "+
			"count to reach an average would report a wait that never happened.", got)
	}
}

func TestAcquireWaitPercentilesTrackTheSlowTail(t *testing.T) {
	var evs []*events.Event
	for i := 0; i < 95; i++ {
		evs = append(evs, acquireWait(10))
	}
	for i := 0; i < 5; i++ {
		evs = append(evs, acquireWait(5000))
	}

	got := AnalyzeAcquireWaits(evs)

	if got.P50 > 11 {
		t.Errorf("P50 = %.2fms, want ~10ms; the median must not be dragged by the tail", got.P50)
	}
	if got.P99 < 4000 {
		t.Errorf("P99 = %.2fms, want it near the 5s tail.\n\nPercentile interpolates "+
			"between neighbouring samples, so a tail has to be wide enough to land on "+
			"rather than be averaged away; an operator reads P99 to find the worst "+
			"acquisitions they actually have.", got.P99)
	}
	if got.Max != 5000*time.Millisecond {
		t.Errorf("Max = %v, want 5s exactly; Max is the one figure that must never "+
			"interpolate", got.Max)
	}
}

func TestAcquireWaitsAreSeparateFromExhaustionWaits(t *testing.T) {
	exhausted := []*events.Event{
		{Type: events.EventPoolExhausted, LatencyNS: 9_000_000_000},
	}
	waits := []*events.Event{acquireWait(50)}

	pool := AnalyzePool(nil, nil, exhausted)
	acquire := AnalyzeAcquireWaits(waits)

	if pool.AvgWaitTime == acquire.Avg {
		t.Error("the two summaries agree, so one is being fed the other's events.\n\n" +
			"PoolStats' wait figures come from pool-exhausted events, which report how " +
			"long a connection has been held, not how long a caller queued. Conflating " +
			"them is the reason the pool.exhaustion rule was withdrawn.")
	}
	if acquire.Avg != 50*time.Millisecond {
		t.Errorf("acquire Avg = %v, want 50ms", acquire.Avg)
	}
}
