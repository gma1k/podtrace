package agent

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/alerting"
	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
)

type captureSender struct {
	mu       sync.Mutex
	received chan *alerting.Alert
}

func (s *captureSender) Name() string { return "capture" }

func (s *captureSender) Send(_ context.Context, alert *alerting.Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case s.received <- alert:
	default:
	}
	return nil
}

func (s *captureSender) await(t *testing.T) *alerting.Alert {
	t.Helper()
	select {
	case alert := <-s.received:
		return alert
	case <-time.After(10 * time.Second):
		t.Fatal("no alert was delivered to the global manager's sender")
		return nil
	}
}

func (s *captureSender) expectNoAlert(t *testing.T) {
	t.Helper()
	select {
	case alert := <-s.received:
		t.Fatalf("expected no alert, got %+v", alert)
	case <-time.After(250 * time.Millisecond):
	}
}

func withCapturingGlobalManager(t *testing.T) *captureSender {
	t.Helper()
	originalEnabled := config.AlertingEnabled
	originalManager := alerting.GetGlobalManager()
	config.AlertingEnabled = true

	sender := &captureSender{received: make(chan *alerting.Alert, 8)}
	manager := &alerting.Manager{}
	manager.EnsureEnabledWithSender(sender)
	alerting.SetGlobalManager(manager)

	t.Cleanup(func() {
		alerting.SetGlobalManager(originalManager)
		config.AlertingEnabled = originalEnabled
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := manager.Shutdown(ctx); err != nil {
			t.Errorf("shutdown alert manager: %v", err)
		}
	})
	return sender
}

func withoutGlobalManager(t *testing.T) {
	t.Helper()
	originalEnabled := config.AlertingEnabled
	originalManager := alerting.GetGlobalManager()
	config.AlertingEnabled = true
	alerting.SetGlobalManager(nil)
	t.Cleanup(func() {
		alerting.SetGlobalManager(originalManager)
		config.AlertingEnabled = originalEnabled
	})
}

func tracedEvent(eventType events.EventType, utilization int32) *events.Event {
	return &events.Event{
		Type:  eventType,
		Error: utilization,
		K8s: &events.K8sMetadata{
			Namespace: "prod",
			PodName:   "checkout-7f",
		},
	}
}

func TestResourceSeverityFromUtilization(t *testing.T) {
	if _, ok := resourceSeverityFromUtilization(int32(config.AlertWarnPct - 1)); ok {
		t.Error("below warn floor must not alert")
	}
	if sev, ok := resourceSeverityFromUtilization(int32(config.AlertWarnPct)); !ok || sev != alerting.SeverityWarning {
		t.Errorf("at warn = (%q, %v), want warning, true", sev, ok)
	}
	if sev, ok := resourceSeverityFromUtilization(int32(config.AlertCritPct)); !ok || sev != alerting.SeverityCritical {
		t.Errorf("at crit = (%q, %v), want critical, true", sev, ok)
	}
	if sev, ok := resourceSeverityFromUtilization(int32(config.AlertEmergPct)); !ok || sev != alerting.SeverityFatal {
		t.Errorf("at emerg = (%q, %v), want fatal, true", sev, ok)
	}
}

func TestEmitTriggerAlert_OOMKillRaisesFatalAlert(t *testing.T) {
	sender := withCapturingGlobalManager(t)

	emitTriggerAlert(tracedEvent(events.EventOOMKill, 0))

	alert := sender.await(t)
	if alert == nil {
		return
	}
	if alert.Source != alerting.AlertSourceOOM {
		t.Errorf("source = %q, want %q", alert.Source, alerting.AlertSourceOOM)
	}
	if alert.Severity != alerting.SeverityFatal {
		t.Errorf("severity = %q, want fatal", alert.Severity)
	}
	if alert.Title != "container OOM-killed" {
		t.Errorf("title = %q", alert.Title)
	}
	if alert.PodName != "checkout-7f" || alert.Namespace != "prod" {
		t.Errorf("pod identity = %s/%s, want prod/checkout-7f", alert.Namespace, alert.PodName)
	}
}

func TestEmitTriggerAlert_ResourceLimitSeverityTracksUtilization(t *testing.T) {
	cases := []struct {
		name        string
		utilization int32
		want        alerting.AlertSeverity
	}{
		{"warn", int32(config.AlertWarnPct), alerting.SeverityWarning},
		{"crit", int32(config.AlertCritPct), alerting.SeverityCritical},
		{"emerg", int32(config.AlertEmergPct), alerting.SeverityFatal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sender := withCapturingGlobalManager(t)

			emitTriggerAlert(tracedEvent(events.EventResourceLimit, tc.utilization))

			alert := sender.await(t)
			if alert == nil {
				return
			}
			if alert.Source != alerting.AlertSourceResourceMonitor {
				t.Errorf("source = %q, want %q", alert.Source, alerting.AlertSourceResourceMonitor)
			}
			if alert.Severity != tc.want {
				t.Errorf("severity = %q, want %q", alert.Severity, tc.want)
			}
			if alert.Title != "resource limit threshold breached" {
				t.Errorf("title = %q", alert.Title)
			}
		})
	}
}

func TestEmitTriggerAlert_IgnoredEvents(t *testing.T) {
	cases := map[string]*events.Event{
		"nil event":                    nil,
		"utilization below warn floor": tracedEvent(events.EventResourceLimit, int32(config.AlertWarnPct-1)),
		"unhandled event type":         tracedEvent(events.EventOpen, 0),
		"no pod metadata":              {Type: events.EventOOMKill},
		"empty pod name":               {Type: events.EventOOMKill, K8s: &events.K8sMetadata{Namespace: "prod"}},
		"empty namespace":              {Type: events.EventOOMKill, K8s: &events.K8sMetadata{PodName: "checkout-7f"}},
	}
	for name, ev := range cases {
		t.Run(name, func(t *testing.T) {
			sender := withCapturingGlobalManager(t)
			emitTriggerAlert(ev)
			sender.expectNoAlert(t)
		})
	}
}

func TestEmitTriggerAlert_NoGlobalManagerIsSafe(t *testing.T) {
	withoutGlobalManager(t)
	emitTriggerAlert(tracedEvent(events.EventOOMKill, 0))
}
