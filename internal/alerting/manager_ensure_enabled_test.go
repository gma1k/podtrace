package alerting

import (
	"context"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/config"
)

func enableAlertingForTest(t *testing.T) {
	t.Helper()
	orig := config.AlertingEnabled
	config.AlertingEnabled = true
	t.Cleanup(func() { config.AlertingEnabled = orig })
}

func shutdownManager(t *testing.T, m *Manager) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := m.Shutdown(ctx); err != nil {
			t.Errorf("shutdown: %v", err)
		}
	})
}

func TestEnsureEnabledWithSender_NilSenderIsNoOp(t *testing.T) {
	m := &Manager{enabled: false}
	m.EnsureEnabledWithSender(nil)
	if m.IsEnabled() {
		t.Error("a nil sender must not enable the manager")
	}
	if len(m.senders) != 0 {
		t.Errorf("senders = %d, want 0", len(m.senders))
	}
}

func TestEnsureEnabledWithSender_EnablesDisabledManager(t *testing.T) {
	m := &Manager{enabled: false}
	m.EnsureEnabledWithSender(&testMockSender{name: "kubernetes-event"})
	shutdownManager(t, m)

	if !m.IsEnabled() {
		t.Fatal("manager must be enabled after EnsureEnabledWithSender")
		return
	}
	if m.deduplicator == nil {
		t.Error("deduplicator must be initialised; SendAlert dereferences it")
	}
	if m.rateLimiter == nil {
		t.Error("rateLimiter must be initialised; SendAlert dereferences it")
	}
	if m.stopCh == nil {
		t.Error("stopCh must be initialised; Shutdown closes it")
	}
	if m.cleanupTicker == nil {
		t.Error("cleanupTicker must be initialised so the dedup cache is pruned")
	}
	if len(m.senders) != 1 {
		t.Errorf("senders = %d, want 1", len(m.senders))
	}
}

func TestEnsureEnabledWithSender_DeliversAlertToRegisteredSender(t *testing.T) {
	enableAlertingForTest(t)

	delivered := make(chan *Alert, 1)
	m := &Manager{enabled: false}
	m.EnsureEnabledWithSender(&testMockSender{
		name: "kubernetes-event",
		sendFunc: func(_ context.Context, alert *Alert) error {
			delivered <- alert
			return nil
		},
	})
	shutdownManager(t, m)

	m.SendAlert(&Alert{
		Severity:  SeverityFatal,
		Title:     "container OOM-killed",
		Message:   "container OOM-killed",
		Source:    AlertSourceOOM,
		PodName:   "checkout-7f",
		Namespace: "prod",
		Timestamp: time.Now(),
	})

	select {
	case got := <-delivered:
		if got.PodName != "checkout-7f" || got.Namespace != "prod" {
			t.Errorf("delivered alert = %+v, want the checkout-7f/prod alert", got)
		}
		if got.Source != AlertSourceOOM {
			t.Errorf("source = %q, want %q", got.Source, AlertSourceOOM)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("alert was never delivered to the sender registered by EnsureEnabledWithSender")
	}
}

func TestEnsureEnabledWithSender_PreservesStateOfEnabledManager(t *testing.T) {
	deduplicator := NewAlertDeduplicator(time.Minute)
	rateLimiter := NewRateLimiter(10)
	m := &Manager{
		enabled:      true,
		deduplicator: deduplicator,
		rateLimiter:  rateLimiter,
		stopCh:       make(chan struct{}),
		senders:      []Sender{&testMockSender{name: "webhook"}},
	}

	m.EnsureEnabledWithSender(&testMockSender{name: "kubernetes-event"})

	if len(m.senders) != 2 {
		t.Errorf("senders = %d, want 2", len(m.senders))
	}
	if m.deduplicator != deduplicator {
		t.Error("existing deduplicator must not be replaced")
	}
	if m.rateLimiter != rateLimiter {
		t.Error("existing rate limiter must not be replaced")
	}
	if m.cleanupTicker != nil {
		t.Error("an already-enabled manager must not gain a second cleanup loop")
	}
}
