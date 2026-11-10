package agent

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/config"
)

type discardSender struct{}

func (discardSender) Send(context.Context, *alerting.Alert) error { return nil }

func (discardSender) Name() string { return "discard" }

func TestTheAgentCountsAlertsItsManagerRateLimits(t *testing.T) {
	origEnabled, origLimit := config.AlertingEnabled, config.AlertRateLimitPerMinute
	t.Cleanup(func() { config.AlertingEnabled, config.AlertRateLimitPerMinute = origEnabled, origLimit })
	config.AlertingEnabled, config.AlertRateLimitPerMinute = true, 2
	t.Setenv("PODTRACE_ALERT_MIN_SEVERITY", "warning")

	manager := &alerting.Manager{}
	manager.EnsureEnabledWithSender(discardSender{})
	metrics := NewMetrics()
	countRateLimitedAlerts(manager, metrics)
	countRateLimitedAlerts(nil, metrics)
	countRateLimitedAlerts(manager, nil)

	for i := 0; i < 5; i++ {
		manager.SendAlert(&alerting.Alert{
			Severity: alerting.SeverityCritical, Title: fmt.Sprintf("t%d", i), Message: "m",
			Timestamp: time.Now(), Source: "test", PodName: "p", Namespace: "shop",
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := manager.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(metrics.AlertsRateLimited.WithLabelValues(alerting.DropReasonNamespaceRateLimit)); got != 3 {
		t.Errorf("namespace drops = %v, want 3 of 5 alerts over a budget of 2", got)
	}
}

func TestTheEventSinkIsExemptFromTheNodeAlertCeiling(t *testing.T) {
	var sender alerting.Sender = newAlertEventSender(newFakeClient())
	scoped, ok := sender.(alerting.NamespaceScopedSender)
	if !ok || !scoped.NamespaceScoped() {
		t.Fatal("the Kubernetes Event sink is not namespace scoped, so another tenant's alerts can starve its flight-recorder triggers")
	}
}

func TestRateLimitedAlertsAreCounted(t *testing.T) {
	m := NewMetrics()
	m.AlertsRateLimited.WithLabelValues(alerting.DropReasonNamespaceRateLimit).Inc()
	m.AlertsRateLimited.WithLabelValues(alerting.DropReasonNodeRateLimit).Add(2)

	if got := testutil.ToFloat64(m.AlertsRateLimited.WithLabelValues(alerting.DropReasonNodeRateLimit)); got != 2 {
		t.Errorf("node drops = %v, want 2", got)
	}
	families, err := m.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() == "podtrace_agent_alerts_rate_limited_total" {
			return
		}
	}
	t.Error("podtrace_agent_alerts_rate_limited_total is not registered")
}
