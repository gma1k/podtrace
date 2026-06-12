package alerting

import (
	"sync"
	"time"
)

type AlertDeduplicator struct {
	seenAlerts map[string]time.Time
	window     time.Duration
	mu         sync.RWMutex
}

func NewAlertDeduplicator(window time.Duration) *AlertDeduplicator {
	return &AlertDeduplicator{
		seenAlerts: make(map[string]time.Time),
		window:     window,
	}
}

func (d *AlertDeduplicator) ShouldSend(alert *Alert) bool {
	if alert == nil {
		return false
	}
	key := alert.Key()
	d.mu.Lock()
	defer d.mu.Unlock()
	if lastSent, exists := d.seenAlerts[key]; exists {
		if time.Since(lastSent) < d.window {
			return false
		}
	}
	d.seenAlerts[key] = time.Now()
	return true
}

// Forget removes the alert's dedup record so the next occurrence is sent
// again. Called when every sender failed: ShouldSend records the alert at
// decision time (so concurrent duplicates do not stampede), but a total
// delivery failure must not silence the alert for the whole window.
func (d *AlertDeduplicator) Forget(alert *Alert) {
	if alert == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.seenAlerts, alert.Key())
}

func (d *AlertDeduplicator) Cleanup(olderThan time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	for key, timestamp := range d.seenAlerts {
		if now.Sub(timestamp) > olderThan {
			delete(d.seenAlerts, key)
		}
	}
}

func (d *AlertDeduplicator) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seenAlerts = make(map[string]time.Time)
}
