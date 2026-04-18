package alerting

import (
	"context"
	"testing"
	"time"
)

// TestCleanupLoop_TickerFires covers the `case <-m.cleanupTicker.C:` branch
// in cleanupLoop by using a very short ticker interval.
func TestCleanupLoop_TickerFires(t *testing.T) {
	m := &Manager{
		enabled:       true,
		deduplicator:  NewAlertDeduplicator(10 * time.Minute),
		rateLimiter:   NewRateLimiter(1000),
		senders:       []Sender{},
		stopCh:        make(chan struct{}),
		cleanupTicker: time.NewTicker(1 * time.Millisecond),
	}
	m.wg.Add(1)
	go m.cleanupLoop()

	// Wait long enough for the ticker to fire at least once.
	time.Sleep(20 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown() unexpected error: %v", err)
	}
}

// TestShutdown_ContextTimeout covers the `case <-ctx.Done(): return ctx.Err()` branch
// in Shutdown — by passing an already-cancelled context while wg is held open.
func TestShutdown_ContextTimeout(t *testing.T) {
	m := &Manager{
		enabled:       true,
		stopCh:        make(chan struct{}),
		cleanupTicker: time.NewTicker(1 * time.Hour),
	}
	// Hold wg so that wg.Wait() never returns within the context deadline.
	m.wg.Add(1)
	// We deliberately do NOT call m.wg.Done() here.

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	// Let the context expire.
	time.Sleep(5 * time.Millisecond)

	err := m.Shutdown(ctx)
	if err == nil {
		t.Error("expected context error from Shutdown, got nil")
	}
	// Release the wg so cleanup doesn't leak goroutines.
	m.wg.Done()
}
