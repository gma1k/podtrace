package alerting

import (
	"context"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/podtrace/podtrace/internal/config"
)

// alertLog is a package-level zap logger for the alerting package.
// It cannot use internal/logger because logger imports alerting (cycle).
var alertLog *zap.Logger

func init() {
	if l, err := zap.NewProduction(); err == nil {
		alertLog = l
	} else {
		alertLog = zap.NewNop()
	}
}

type Manager struct {
	senders       []Sender
	deduplicator  *AlertDeduplicator
	rateLimiter   *RateLimiter
	enabled       bool
	mu            sync.RWMutex
	cleanupTicker *time.Ticker
	stopCh        chan struct{}
	stopOnce      sync.Once
	shuttingDown  bool
	wg            sync.WaitGroup
}

// deliveryBudget is the per-alert deadline handed to each sender. It must
// cover the sender's full retry schedule — maxRetries+1 attempts, each up
// to the HTTP timeout, plus the exponential backoff sleeps between them —
// or the deadline expires mid-schedule and the configured retries are
// dead config. (The previous 2×HTTP-timeout budget allowed roughly one
// retry of the default schedule.)
func deliveryBudget() time.Duration {
	budget := time.Duration(config.AlertMaxRetries+1) * config.AlertHTTPTimeout
	for attempt := 1; attempt <= config.AlertMaxRetries; attempt++ {
		backoff := config.DefaultAlertRetryBackoffBase * time.Duration(1<<uint(attempt-1))
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
		budget += backoff
	}
	return budget + 5*time.Second
}

// redactURLForLog returns a URL safe to log (query and fragment stripped).
func redactURLForLog(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "[invalid-url]"
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func NewManager() (*Manager, error) {
	if !config.AlertingEnabled {
		return &Manager{enabled: false}, nil
	}
	manager := &Manager{
		senders:      make([]Sender, 0),
		deduplicator: NewAlertDeduplicator(config.AlertDeduplicationWindow),
		rateLimiter:  NewRateLimiter(config.AlertRateLimitPerMinute),
		enabled:      true,
		stopCh:       make(chan struct{}),
	}
	if config.AlertWebhookURL != "" {
		webhookSender, err := NewWebhookSender(config.AlertWebhookURL, config.AlertHTTPTimeout)
		if err != nil {
			alertLog.Warn("Failed to create webhook alert sender — alerts will not be delivered via webhook",
				zap.Error(err), zap.String("url", redactURLForLog(config.AlertWebhookURL)))
		} else {
			retrySender := NewRetrySender(webhookSender, config.AlertMaxRetries, config.DefaultAlertRetryBackoffBase)
			manager.senders = append(manager.senders, retrySender)
		}
	}
	if config.AlertSlackWebhookURL != "" {
		slackSender, err := NewSlackSender(config.AlertSlackWebhookURL, config.AlertSlackChannel, config.AlertHTTPTimeout)
		if err != nil {
			alertLog.Warn("Failed to create Slack alert sender — alerts will not be delivered via Slack",
				zap.Error(err))
		} else {
			retrySender := NewRetrySender(slackSender, config.AlertMaxRetries, config.DefaultAlertRetryBackoffBase)
			manager.senders = append(manager.senders, retrySender)
		}
	}
	if config.AlertSplunkEnabled {
		splunkEndpoint := config.GetSplunkEndpoint()
		splunkToken := config.GetSplunkToken()
		if splunkEndpoint != "" && splunkToken != "" {
			splunkSender, err := NewSplunkAlertSender(splunkEndpoint, splunkToken, config.AlertHTTPTimeout)
			if err != nil {
				alertLog.Warn("Failed to create Splunk alert sender — alerts will not be delivered via Splunk",
					zap.Error(err), zap.String("endpoint", redactURLForLog(splunkEndpoint)))
			} else {
				retrySender := NewRetrySender(splunkSender, config.AlertMaxRetries, config.DefaultAlertRetryBackoffBase)
				manager.senders = append(manager.senders, retrySender)
			}
		}
	}
	if len(manager.senders) == 0 {
		return &Manager{enabled: false}, nil
	}
	manager.cleanupTicker = time.NewTicker(1 * time.Hour)
	manager.wg.Add(1)
	go manager.cleanupLoop()
	return manager, nil
}

func (m *Manager) SendAlert(alert *Alert) {
	if !m.enabled || alert == nil {
		return
	}
	if !ShouldSendAlert(alert.Severity) {
		return
	}
	if !m.rateLimiter.Allow() {
		return
	}
	if !m.deduplicator.ShouldSend(alert) {
		return
	}
	m.mu.RLock()
	if m.shuttingDown {
		m.mu.RUnlock()
		return
	}
	senders := make([]Sender, len(m.senders))
	copy(senders, m.senders)
	// wg.Add must happen before RUnlock so Shutdown cannot observe a zero
	// counter between the shutting-down check and the goroutine spawn.
	m.wg.Add(len(senders) + 1)
	m.mu.RUnlock()

	// Fan out one goroutine per sender, each with its OWN copy of the
	// alert: senders mutate it (Sanitize truncates fields), and a shared
	// pointer raced sibling goroutines marshaling it concurrently.
	var successes atomic.Int64
	var deliveries sync.WaitGroup
	for _, sender := range senders {
		deliveries.Add(1)
		go func(s Sender, a *Alert) {
			defer m.wg.Done()
			defer deliveries.Done()
			ctx, cancel := context.WithTimeout(context.Background(), deliveryBudget())
			defer cancel()
			if err := s.Send(ctx, a); err != nil {
				alertLog.Warn("Alert delivery failed",
					zap.String("sender", s.Name()),
					zap.String("alert", a.Title),
					zap.Error(err))
			} else {
				successes.Add(1)
			}
		}(sender, alert.Clone())
	}
	go func() {
		defer m.wg.Done()
		deliveries.Wait()
		if successes.Load() == 0 {
			// Every sender failed: forget the dedup record so the next
			// occurrence is attempted again instead of being silenced for
			// the rest of the window.
			m.deduplicator.Forget(alert)
		}
	}()
}

func (m *Manager) cleanupLoop() {
	defer m.wg.Done()
	for {
		select {
		case <-m.stopCh:
			return
		case <-m.cleanupTicker.C:
			m.deduplicator.Cleanup(config.AlertDeduplicationWindow * 2)
		}
	}
}

// Shutdown waits for in-flight alert deliveries (bounded by ctx) and is
// idempotent — a second call no longer panics on the closed stop channel.
func (m *Manager) Shutdown(ctx context.Context) error {
	if !m.enabled {
		return nil
	}
	m.mu.Lock()
	m.shuttingDown = true
	m.mu.Unlock()
	m.stopOnce.Do(func() {
		close(m.stopCh)
	})
	if m.cleanupTicker != nil {
		m.cleanupTicker.Stop()
	}
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) AddSender(sender Sender) {
	if sender == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.senders = append(m.senders, sender)
}

func (m *Manager) IsEnabled() bool {
	return m.enabled
}
