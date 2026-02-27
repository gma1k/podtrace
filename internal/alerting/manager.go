package alerting

import (
	"context"
	"sync"
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
	wg            sync.WaitGroup
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
				zap.Error(err), zap.String("url", config.AlertWebhookURL))
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
					zap.Error(err), zap.String("endpoint", splunkEndpoint))
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
	senders := make([]Sender, len(m.senders))
	copy(senders, m.senders)
	m.mu.RUnlock()
		for _, sender := range senders {
			go func(s Sender) {
				ctx, cancel := context.WithTimeout(context.Background(), config.AlertHTTPTimeout*2)
				defer cancel()
				_ = s.Send(ctx, alert)
			}(sender)
		}
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

func (m *Manager) Shutdown(ctx context.Context) error {
	if !m.enabled {
		return nil
	}
	close(m.stopCh)
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

