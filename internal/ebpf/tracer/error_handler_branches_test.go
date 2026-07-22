package tracer

import (
	"testing"
	"time"
)

func TestNewSlidingWindow_NonPositiveBucketsClampsToOne(t *testing.T) {
	for _, n := range []int{0, -1, -100} {
		sw := newSlidingWindow(5*time.Second, n)
		if sw.numBuckets != 1 {
			t.Errorf("newSlidingWindow(_, %d).numBuckets = %d, want 1", n, sw.numBuckets)
		}
		if cap(sw.buckets) != 1 {
			t.Errorf("newSlidingWindow(_, %d) bucket capacity = %d, want 1", n, cap(sw.buckets))
		}
	}
}

func TestCircuitBreaker_RecordFailureFromHalfOpenReopens(t *testing.T) {
	cb := newCircuitBreaker(2, time.Minute)
	cb.recordFailure()
	cb.recordFailure()

	cb.mu.Lock()
	cb.state = circuitBreakerHalfOpen
	cb.successCount = 2
	cb.mu.Unlock()

	cb.recordFailure()

	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.state != circuitBreakerOpen {
		t.Errorf("state after failure in half-open = %d, want open (%d)", cb.state, circuitBreakerOpen)
	}
	if cb.successCount != 0 {
		t.Errorf("successCount after reopen = %d, want 0", cb.successCount)
	}
}

func TestCircuitBreaker_CanProceedInHalfOpenReturnsTrue(t *testing.T) {
	cb := newCircuitBreaker(2, time.Minute)

	cb.mu.Lock()
	cb.state = circuitBreakerHalfOpen
	cb.mu.Unlock()

	if !cb.canProceed() {
		t.Error("canProceed in half-open state = false, want true")
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.state != circuitBreakerHalfOpen {
		t.Errorf("canProceed changed half-open state to %d, want it left half-open (%d)", cb.state, circuitBreakerHalfOpen)
	}
}
