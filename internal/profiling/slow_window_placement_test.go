package profiling

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/clock"
	"github.com/gma1k/podtrace/internal/events"
)

func TestHotFramesComeFromWhileTheSlowOperationRan(t *testing.T) {
	returned := time.Now()
	const latency = 400 * time.Millisecond
	all := []*events.Event{
		{
			Type:      events.EventDBQuery,
			LatencyNS: uint64(latency),
			Timestamp: clock.WallToBPFTimestamp(returned),
		},
		{
			Type:      events.EventSchedSwitch,
			PID:       1,
			Stack:     []uint64{0xd0d0},
			Timestamp: clock.WallToBPFTimestamp(returned.Add(-latency / 2)),
		},
		{
			Type:      events.EventSchedSwitch,
			PID:       1,
			Stack:     []uint64{0xafe7},
			Timestamp: clock.WallToBPFTimestamp(returned.Add(latency / 2)),
		},
	}

	result := Correlate(context.Background(), all, nil, nil, 1, nil)

	var frames []string
	for _, f := range result.HotFrames {
		frames = append(frames, f.Frame)
	}
	joined := strings.Join(frames, " ")
	if !strings.Contains(joined, "d0d0") {
		t.Errorf("hot frames %v miss the frame sampled while the query ran", frames)
	}
	if strings.Contains(joined, "afe7") {
		t.Errorf("hot frames %v include a frame sampled after the query returned", frames)
	}
}

func TestSlowEventWindowSpansTheOperationPlusTheMargin(t *testing.T) {
	returned := time.Now()
	w := slowEventWindow(&events.Event{LatencyNS: uint64(time.Second), Timestamp: clock.WallToBPFTimestamp(returned)})
	if got := w.end.Sub(returned); got < slowWindowMargin-time.Millisecond || got > slowWindowMargin+time.Millisecond {
		t.Errorf("window ends %v after the return, want %v", got, slowWindowMargin)
	}
	if got := returned.Sub(w.start); got < time.Second+slowWindowMargin-time.Millisecond || got > time.Second+slowWindowMargin+time.Millisecond {
		t.Errorf("window starts %v before the return, want the latency plus %v", got, slowWindowMargin)
	}
}
