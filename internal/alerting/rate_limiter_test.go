package alerting

import (
	"testing"
	"time"
)

func TestRateLimiter_Allow(t *testing.T) {
	rl := NewRateLimiter(5)
	for i := 0; i < 5; i++ {
		if !rl.Allow() {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}
	if rl.Allow() {
		t.Error("Request 6 should not be allowed (rate limit exceeded)")
	}
}

func TestRateLimiter_Allow_TimeWindow(t *testing.T) {
	rl := NewRateLimiterWithWindow(2, 50*time.Millisecond)
	if !rl.Allow() {
		t.Error("First request should be allowed")
	}
	if !rl.Allow() {
		t.Error("Second request should be allowed")
	}
	if rl.Allow() {
		t.Error("Third request should not be allowed")
	}
	time.Sleep(70 * time.Millisecond)
	if !rl.Allow() {
		t.Error("Request after window should be allowed")
	}
}

func TestRateLimiter_Reset(t *testing.T) {
	rl := NewRateLimiter(2)
	rl.Allow()
	rl.Allow()
	if rl.Allow() {
		t.Error("Request should not be allowed after limit")
	}
	rl.Reset()
	if !rl.Allow() {
		t.Error("Request should be allowed after reset")
	}
}

func TestNamespaceRateLimiterKeepsSeparateBudgets(t *testing.T) {
	n := NewNamespaceRateLimiter(2)
	now := time.Now()
	for i := 0; i < 2; i++ {
		if !n.allowAt("a", now) {
			t.Fatalf("namespace a admission %d refused inside its budget", i)
		}
	}
	if n.allowAt("a", now) {
		t.Error("namespace a exceeded its budget")
	}
	if !n.allowAt("b", now) {
		t.Error("namespace b was refused because namespace a spent its own budget")
	}
	if !n.allowAt("a", now.Add(time.Minute+time.Millisecond)) {
		t.Error("namespace a stayed refused after its window passed")
	}
}

func TestNamespaceRateLimiterCleanupForgetsIdleNamespaces(t *testing.T) {
	n := NewNamespaceRateLimiter(5)
	now := time.Now()
	n.allowAt("gone", now)
	n.allowAt("active", now.Add(50*time.Second))
	n.cleanupAt(now.Add(70 * time.Second))
	if got := n.namespaces(); got != 1 {
		t.Errorf("namespaces kept = %d, want only the one still inside its window", got)
	}
	if !n.allowAt("gone", now.Add(70*time.Second)) {
		t.Error("a forgotten namespace was not given a fresh budget")
	}
}

func TestNamespaceRateLimiterWithZeroLimitAdmitsNothing(t *testing.T) {
	n := NewNamespaceRateLimiter(0)
	if n.Allow("a") {
		t.Error("a zero limit admitted an alert")
	}
}

func TestRateLimiterWithNegativeLimitAdmitsNothing(t *testing.T) {
	if NewRateLimiter(-1).Allow() {
		t.Error("a negative limit admitted an alert")
	}
}
