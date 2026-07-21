package agent

import "testing"

func TestErrorRateDetector_RecoversWithinActiveWindow(t *testing.T) {
	d, _ := newTestDetector(t, 50)

	edges := 0
	for i := 0; i < errorRateMinSampleSize; i++ {
		if d.Observe(true) {
			edges++
		}
	}
	if edges != 1 {
		t.Fatalf("expected exactly one breach edge, got %d", edges)
	}
	if !d.IsBreached() {
		t.Fatal("detector should be breached after the error burst")
	}

	for i := 0; i < errorRateMinSampleSize; i++ {
		if d.Observe(false) {
			t.Fatalf("success observation %d should never produce a breach edge", i)
		}
	}
	if d.IsBreached() {
		t.Error("breach should have cleared once the diluted rate dropped to the threshold")
	}
}
