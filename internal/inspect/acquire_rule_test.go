package inspect

import (
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
)

func acquireWaitWindow(prevCount uint64, prevSum float64, curCount uint64, curSum float64) ([]*dto.MetricFamily, []*dto.MetricFamily) {
	prev := []*dto.MetricFamily{histogramFamily(familyAcquire,
		histogram(prevCount, prevSum, workloadLabels()...))}
	cur := []*dto.MetricFamily{histogramFamily(familyAcquire,
		histogram(curCount, curSum, workloadLabels()...))}
	return prev, cur
}

func TestAcquireLatencyFiresOnASustainedMeanWait(t *testing.T) {
	prev, cur := acquireWaitWindow(10, 0.5, 60, 15.5)

	got := evalOnce(t, acquireLatencyRule(), prev, cur, time.Minute)
	if len(got) != 1 {
		t.Fatalf("got %d issues, want 1: %v", len(got), got)
	}
	if got[0].ID != "db.connection_acquire_slow" {
		t.Errorf("issue id = %q, want db.connection_acquire_slow", got[0].ID)
	}
	if got[0].Subject.Workload != "checkout" {
		t.Errorf("subject workload = %q, want checkout", got[0].Subject.Workload)
	}
}

func TestAcquireLatencyUsesMeanWaitNotWaitCount(t *testing.T) {
	prev, cur := acquireWaitWindow(0, 0, 100_000, 1.0)

	if got := evalOnce(t, acquireLatencyRule(), prev, cur, time.Minute); len(got) != 0 {
		t.Errorf("fired on 100000 acquisitions averaging 10us each: %v\n\n"+
			"A high wait count is not saturation. Keying on the count would make every "+
			"busy pool look exhausted, and the operator would learn to ignore the issue.",
			got)
	}
}

func TestAcquireLatencyStaysSilentWhenNothingWaited(t *testing.T) {
	prev, cur := acquireWaitWindow(7, 3.5, 7, 3.5)

	if got := evalOnce(t, acquireLatencyRule(), prev, cur, time.Minute); len(got) != 0 {
		t.Errorf("fired with no new waiting acquisitions in the window: %v\n\n"+
			"The metric only records acquisitions that blocked, so a healthy pool adds no "+
			"samples. Dividing a zero delta must not resurrect the previous window's mean.",
			got)
	}
}

func TestAcquireLatencyIgnoresACounterReset(t *testing.T) {
	prev, cur := acquireWaitWindow(500, 250.0, 3, 1.5)

	if got := evalOnce(t, acquireLatencyRule(), prev, cur, time.Minute); len(got) != 0 {
		t.Errorf("fired across a counter reset: %v\n\nA restarted pod rewinds the "+
			"histogram, and treating that as a window would invent a wait that never "+
			"happened.", got)
	}
}

func TestAcquireLatencyReportsTheMeanAndTheCountAsEvidence(t *testing.T) {
	prev, cur := acquireWaitWindow(0, 0, 4, 2.0)

	got := evalOnce(t, acquireLatencyRule(), prev, cur, time.Minute)
	if len(got) != 1 {
		t.Fatalf("got %d issues, want 1", len(got))
	}

	byName := map[string]float64{}
	for _, ev := range got[0].Evidence {
		byName[ev.Name] = ev.Value
	}
	if got := byName["mean_acquire_time"]; got != 0.5 {
		t.Errorf("mean_acquire_time = %v, want 0.5 (2s over 4 acquisitions)", got)
	}
	if got := byName["waiting_acquisitions"]; got != 4 {
		t.Errorf("waiting_acquisitions = %v, want 4", got)
	}
}

func TestAFirstTickLifetimeTotalNeverActivatesAnIssue(t *testing.T) {
	h := newHarness(t, acquireLatencyRule())

	h.serve(histogramFamily(familyAcquire,
		histogram(60, 30.0, workloadLabels()...)))
	if got := h.evaluate(t); len(got) != 0 {
		t.Fatalf("activated on the very first evaluation: %v", got)
	}

	h.advance(3 * time.Minute)
	h.serve(histogramFamily(familyAcquire,
		histogram(61, 30.01, workloadLabels()...)))

	if got := h.evaluate(t); len(got) != 0 {
		t.Errorf("activated %v after a healthy second window.\n\nOn its first evaluation "+
			"the engine has no previous snapshot, so Deltas reports a pre-existing pod's "+
			"whole lifetime counter as one window and the rule does fire. The hold time is "+
			"what must absorb that: by the next evaluation the window is real, the mean is "+
			"back under threshold, and the pending condition has to be cleared rather than "+
			"promoted.", got)
	}
}
