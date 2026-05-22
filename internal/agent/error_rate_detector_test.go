package agent

import (
	"sync"
	"testing"
	"time"
)

// fakeClock advances only when the test asks it to, so detector tests
// stay deterministic regardless of CI load.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Unix(1_700_000_000, 0)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newTestDetector(t *testing.T, threshold int32) (*errorRateDetector, *fakeClock) {
	t.Helper()
	clk := newFakeClock()
	d := newErrorRateDetector(threshold)
	d.nowFn = clk.Now
	return d, clk
}

// TestErrorRateDetector_BelowMinSampleSizeNeverBreaches guards the
// startup-noise contract: a CR that sees one error in its first second
// must not breach a 50% threshold.
func TestErrorRateDetector_BelowMinSampleSizeNeverBreaches(t *testing.T) {
	d, _ := newTestDetector(t, 50)
	for i := 0; i < errorRateMinSampleSize-1; i++ {
		if got := d.Observe(true); got {
			t.Fatalf("observation %d: unexpected breach below min sample size", i)
		}
	}
}

// TestErrorRateDetector_EdgeTriggeredBreach pins the "one signal per
// transition" contract, sustained breach must not produce repeated
// edge signals.
func TestErrorRateDetector_EdgeTriggeredBreach(t *testing.T) {
	d, _ := newTestDetector(t, 10)
	// 20 events, all errors → rate = 100% > 10% threshold.
	edges := 0
	for i := 0; i < errorRateMinSampleSize+5; i++ {
		if d.Observe(true) {
			edges++
		}
	}
	if edges != 1 {
		t.Errorf("expected exactly one breach edge, got %d", edges)
	}
}

// TestErrorRateDetector_RateBelowThresholdNoBreach ensures the
// arithmetic correctly compares against the threshold.
func TestErrorRateDetector_RateBelowThresholdNoBreach(t *testing.T) {
	d, _ := newTestDetector(t, 30)
	// 30 events: 5 errors, 25 successes to rate ≈ 16.7%, below 30%.
	for i := 0; i < 5; i++ {
		if d.Observe(true) {
			t.Fatalf("event %d: unexpected breach", i)
		}
	}
	for i := 0; i < 25; i++ {
		if d.Observe(false) {
			t.Fatalf("event %d (success): unexpected breach", i)
		}
	}
	if d.IsBreached() {
		t.Error("detector should not be in breached state")
	}
}

// TestErrorRateDetector_WindowExpiresClearsBreach asserts that old
// buckets fall out of the window.
func TestErrorRateDetector_WindowExpiresClearsBreach(t *testing.T) {
	d, clk := newTestDetector(t, 10)
	for i := 0; i < errorRateMinSampleSize+5; i++ {
		d.Observe(true)
	}
	if !d.IsBreached() {
		t.Fatal("expected breach after error burst")
	}

	clk.Advance(time.Duration(errorRateWindowSeconds+1) * time.Second)
	d.Observe(false)
	if d.IsBreached() {
		t.Error("breach should clear after window expiry")
	}
}

// TestErrorRateDetector_ThresholdUpdatePreservesWindow guards the
// "bundle rotation does not lose window state" property: changing the
// threshold while the detector is healthy must keep buckets in place.
func TestErrorRateDetector_ThresholdUpdatePreservesWindow(t *testing.T) {
	d, _ := newTestDetector(t, 100) // threshold so high nothing breaches
	for i := 0; i < errorRateMinSampleSize; i++ {
		d.Observe(true)
	}
	if d.IsBreached() {
		t.Fatal("100% threshold means errors=total is at-not-above; should not breach")
	}

	d.setThreshold(10)
	if !d.Observe(true) {
		t.Error("expected breach edge after threshold tighten on existing window")
	}
}

// TestErrorRateDetector_BucketRollover exercises the
// ring-modulo-window-seconds index reset when the clock wraps a full
// minute and the same slot is revisited with a newer second.
func TestErrorRateDetector_BucketRollover(t *testing.T) {
	d, clk := newTestDetector(t, 10)
	// 20 errors at t=0.
	for i := 0; i < 20; i++ {
		d.Observe(true)
	}
	clk.Advance(time.Duration(errorRateWindowSeconds) * time.Second)
	for i := 0; i < 20; i++ {
		d.Observe(false)
	}
	if d.IsBreached() {
		t.Error("breach should clear when window fully rolls over with successes")
	}
}

// TestErrorRateDetector_ConcurrentObserveSafe is a smoke test for the
// internal mutex.
func TestErrorRateDetector_ConcurrentObserveSafe(t *testing.T) {
	d, _ := newTestDetector(t, 50)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				d.Observe(true)
			}
		}()
	}
	wg.Wait()
	if !d.IsBreached() {
		t.Error("8 goroutines × 200 errors should produce a breach")
	}
}

// TestErrorRateDetector_QuietPeriodClearsLatentBreach pins the
// "breach holds during sustained activity, clears during quiet" path.
func TestErrorRateDetector_QuietPeriodClearsLatentBreach(t *testing.T) {
	d, clk := newTestDetector(t, 10)
	for i := 0; i < errorRateMinSampleSize+5; i++ {
		d.Observe(true)
	}
	if !d.IsBreached() {
		t.Fatal("expected breach")
	}
	clk.Advance(time.Duration(errorRateWindowSeconds+1) * time.Second)
	d.Observe(false)
	if d.IsBreached() {
		t.Error("breach should clear when windowed total drops below min sample")
	}
}