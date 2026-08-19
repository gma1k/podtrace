package alerting

import (
	"testing"
	"time"
)

func TestCappedBackoff_NeverNegativeOrOverCap(t *testing.T) {
	base := time.Second
	for attempt := 1; attempt <= 1000; attempt++ {
		b := cappedBackoff(base, attempt)
		if b < 0 {
			t.Fatalf("attempt %d produced a negative backoff %v (overflow)", attempt, b)
		}
		if b > maxAlertBackoff {
			t.Fatalf("attempt %d produced %v, exceeding the %v cap", attempt, b, maxAlertBackoff)
		}
	}
}

func TestCappedBackoff_ExponentialThenCapped(t *testing.T) {
	base := time.Second
	if got := cappedBackoff(base, 1); got != time.Second {
		t.Errorf("attempt 1 = %v, want 1s", got)
	}
	if got := cappedBackoff(base, 3); got != 4*time.Second {
		t.Errorf("attempt 3 = %v, want 4s", got)
	}
	if got := cappedBackoff(base, 40); got != maxAlertBackoff {
		t.Errorf("attempt 40 = %v, want the %v cap (not a wrapped negative)", got, maxAlertBackoff)
	}
}
