package analyzer

import (
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func capacitySample(numOpen uint64, maxOpen uint32, percent int32) *events.Event {
	return &events.Event{
		Type:     events.EventDBPoolStats,
		Bytes:    numOpen,
		TCPState: maxOpen,
		Error:    percent,
	}
}

func TestPoolCapacityKeepsThePeakRatherThanTheLastSample(t *testing.T) {
	got := AnalyzePoolCapacity([]*events.Event{
		capacitySample(3, 20, 15),
		capacitySample(19, 20, 95),
		capacitySample(4, 20, 20),
	})

	if got.Samples != 3 {
		t.Errorf("Samples = %d, want 3", got.Samples)
	}
	if got.PeakOpen != 19 || got.PeakPercent != 95 {
		t.Errorf("peak = %d open / %d%%, want 19 / 95; a pool that filled up and drained "+
			"reads as healthy if only the last sample survives", got.PeakOpen, got.PeakPercent)
	}
	if !got.Limited || got.MaxOpen != 20 {
		t.Errorf("limit = %d (limited=%v), want 20", got.MaxOpen, got.Limited)
	}
}

func TestAnUnlimitedPoolHasACountButNoPercentage(t *testing.T) {
	got := AnalyzePoolCapacity([]*events.Event{
		capacitySample(12, 0, 0),
		capacitySample(41, 0, 0),
	})

	if got.PeakOpen != 41 {
		t.Errorf("PeakOpen = %d, want 41", got.PeakOpen)
	}
	if got.Limited {
		t.Error("an unlimited pool was reported as limited, so the report would claim a " +
			"utilization against a ceiling that does not exist")
	}
}

func TestAPoolThatGainsALimitMidTraceReportsIt(t *testing.T) {
	got := AnalyzePoolCapacity([]*events.Event{
		capacitySample(12, 0, 0),
		capacitySample(9, 10, 90),
	})

	if !got.Limited || got.MaxOpen != 10 || got.PeakPercent != 90 {
		t.Errorf("got %+v, want the limit SetMaxOpenConns installed while the trace ran", got)
	}
}

func TestPoolCapacitySkipsUnusableSamples(t *testing.T) {
	got := AnalyzePoolCapacity([]*events.Event{
		nil,
		capacitySample(900, 20, -1),
		capacitySample(7, 20, 35),
	})

	if got.Samples != 1 {
		t.Errorf("Samples = %d, want 1; a nil entry or a negative percentage is not a "+
			"reading", got.Samples)
	}
	if got.PeakOpen != 7 {
		t.Errorf("PeakOpen = %d, want 7; the rejected sample's count was counted anyway",
			got.PeakOpen)
	}
}

func TestPoolCapacityOfNothingIsEmpty(t *testing.T) {
	if got := AnalyzePoolCapacity(nil); got.Samples != 0 || got.PeakOpen != 0 || got.Limited {
		t.Errorf("got %+v, want a zero summary", got)
	}
}
