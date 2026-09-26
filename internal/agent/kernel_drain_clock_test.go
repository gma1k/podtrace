package agent

import (
	"math"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestTheDrainClockIsPublished(t *testing.T) {
	m := NewMetrics()
	if got := m.secondsSinceKernelDrain(); got != -1 {
		t.Errorf("seconds since drain before any drain = %v, want -1 so a reader knows there is no clock yet", got)
	}
	at := time.Now().Add(-3 * time.Second)
	m.RecordKernelDrainTime(at, 10*time.Second)

	if got := testutil.ToFloat64(m.KernelDrainedAt); math.Abs(got-float64(at.UnixNano())/1e9) > 1e-3 {
		t.Errorf("drained timestamp = %v", got)
	}
	if got := testutil.ToFloat64(m.KernelDrainInterval); got != 10 {
		t.Errorf("drain interval = %v", got)
	}
	if got := testutil.ToFloat64(m.KernelSinceDrain); got < 3 || got > 4 {
		t.Errorf("seconds since drain = %v, want about 3, measured when read", got)
	}
}

func TestRecordingADrainOnNoMetricsIsSafe(t *testing.T) {
	var nothing *Metrics
	nothing.RecordKernelDrainTime(time.Now(), time.Second)
	(&Metrics{}).RecordKernelDrainTime(time.Now(), time.Second)
}
