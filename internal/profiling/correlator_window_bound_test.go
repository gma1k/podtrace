package profiling

import (
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/clock"
	"github.com/gma1k/podtrace/internal/events"
)

func TestCorrelate_FrameWindowsBoundedToRetainedSlowEvents(t *testing.T) {
	base := time.Now()
	var all []*events.Event

	for i := 0; i < maxCorrelatedSlowEvents; i++ {
		all = append(all, &events.Event{
			Type:      events.EventDNS,
			LatencyNS: 5_000_000,
			Timestamp: clock.WallToBPFTimestamp(base.Add(time.Duration(i) * time.Second)),
		})
	}

	droppedAt := base.Add(1000 * time.Second)
	all = append(all, &events.Event{
		Type:      events.EventDNS,
		LatencyNS: 1_000_000,
		Timestamp: clock.WallToBPFTimestamp(droppedAt),
	})
	all = append(all, &events.Event{
		Type:      events.EventSchedSwitch,
		LatencyNS: 1000,
		Stack:     []uint64{0xdeadbeef},
		Timestamp: clock.WallToBPFTimestamp(droppedAt),
	})

	result := Correlate(all, nil, nil, 0.5)

	if len(result.SlowEvents) != maxCorrelatedSlowEvents {
		t.Fatalf("SlowEvents = %d, want capped at %d", len(result.SlowEvents), maxCorrelatedSlowEvents)
	}
	if len(result.HotFrames) != 0 {
		t.Fatalf("a SchedSwitch inside only a dropped (rank>%d) slow window must not aggregate; HotFrames = %+v",
			maxCorrelatedSlowEvents, result.HotFrames)
	}
}
