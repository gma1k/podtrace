package alerting

import (
	"sync"
	"time"
)

type RateLimiter struct {
	limit  int
	window time.Duration
	counts []time.Time
	mu     sync.Mutex
}

func NewRateLimiter(limitPerMinute int) *RateLimiter {
	return NewRateLimiterWithWindow(limitPerMinute, time.Minute)
}

// NewRateLimiterWithWindow allows the sliding window to be set explicitly.
func NewRateLimiterWithWindow(limit int, window time.Duration) *RateLimiter {
	capacity := limit
	if capacity < 0 {
		capacity = 0
	}
	return &RateLimiter{
		limit:  limit,
		window: window,
		counts: make([]time.Time, 0, capacity),
	}
}

func (rl *RateLimiter) Allow() bool {
	return rl.allowAt(time.Now())
}

func (rl *RateLimiter) allowAt(now time.Time) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.expire(now)
	if len(rl.counts) >= rl.limit {
		return false
	}
	rl.counts = append(rl.counts, now)
	return true
}

// expire drops the timestamps that have left the sliding window. The caller
// holds rl.mu.
func (rl *RateLimiter) expire(now time.Time) {
	cutoff := now.Add(-rl.window)
	kept := rl.counts[:0]
	for _, t := range rl.counts {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	rl.counts = kept
}

// idle reports whether no admission is still inside the window, so the
// limiter carries no state worth keeping.
func (rl *RateLimiter) idle(now time.Time) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.expire(now)
	return len(rl.counts) == 0
}

func (rl *RateLimiter) Reset() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.counts = rl.counts[:0]
}

// NamespaceRateLimiter gives every namespace its own sliding-window budget,
// so one tenant's alert storm spends only that tenant's budget instead of
// silencing every other namespace on the node.
type NamespaceRateLimiter struct {
	limit    int
	window   time.Duration
	mu       sync.Mutex
	limiters map[string]*RateLimiter
}

func NewNamespaceRateLimiter(limitPerMinute int) *NamespaceRateLimiter {
	return NewNamespaceRateLimiterWithWindow(limitPerMinute, time.Minute)
}

func NewNamespaceRateLimiterWithWindow(limit int, window time.Duration) *NamespaceRateLimiter {
	return &NamespaceRateLimiter{
		limit:    limit,
		window:   window,
		limiters: make(map[string]*RateLimiter),
	}
}

// Allow spends one admission from namespace's budget. Alerts with no
// namespace (the agent's own log alerts) share the "" budget.
func (n *NamespaceRateLimiter) Allow(namespace string) bool {
	return n.allowAt(namespace, time.Now())
}

func (n *NamespaceRateLimiter) allowAt(namespace string, now time.Time) bool {
	n.mu.Lock()
	limiter, ok := n.limiters[namespace]
	if !ok {
		limiter = NewRateLimiterWithWindow(n.limit, n.window)
		n.limiters[namespace] = limiter
	}
	n.mu.Unlock()
	return limiter.allowAt(now)
}

// Cleanup forgets namespaces whose window holds no admissions, so namespace
// churn cannot grow the map for the life of the agent.
func (n *NamespaceRateLimiter) Cleanup() {
	n.cleanupAt(time.Now())
}

func (n *NamespaceRateLimiter) cleanupAt(now time.Time) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for namespace, limiter := range n.limiters {
		if limiter.idle(now) {
			delete(n.limiters, namespace)
		}
	}
}

func (n *NamespaceRateLimiter) namespaces() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.limiters)
}
