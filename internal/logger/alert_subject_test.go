package logger

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/config"
)

func capturedAlerts(t *testing.T) <-chan map[string]any {
	t.Helper()
	got := make(chan map[string]any, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		_ = json.NewDecoder(r.Body).Decode(&payload)
		got <- payload
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	origEnabled, origURL := config.AlertingEnabled, config.AlertWebhookURL
	t.Setenv("PODTRACE_ALERT_MIN_SEVERITY", "warning")
	config.AlertingEnabled, config.AlertWebhookURL = true, srv.URL
	manager, err := alerting.NewManager()
	if err != nil {
		t.Fatal(err)
	}
	if !manager.IsEnabled() {
		t.Skip("manager disabled")
	}
	alerting.SetGlobalManager(manager)
	t.Cleanup(func() {
		alerting.SetGlobalManager(nil)
		config.AlertingEnabled, config.AlertWebhookURL = origEnabled, origURL
		SetAlertSubject("", "")
	})
	return got
}

func nextAlert(t *testing.T, got <-chan map[string]any) map[string]any {
	t.Helper()
	select {
	case a := <-got:
		return a
	case <-time.After(5 * time.Second):
		t.Fatal("no alert delivered")
		return nil
	}
}

func TestALogAlertNamesThePodTheProcessTraces(t *testing.T) {
	got := capturedAlerts(t)
	SetAlertSubject("checkout-7d9f", "shop")
	Warn("pprof endpoint unreachable on the traced pod")
	if a := nextAlert(t, got); a["pod"] != "checkout-7d9f" || a["namespace"] != "shop" {
		t.Errorf("alert pod=%v namespace=%v, want checkout-7d9f/shop", a["pod"], a["namespace"])
	}
}

func TestALogAlertNamesNoPodWhenNoneIsSet(t *testing.T) {
	got := capturedAlerts(t)
	SetAlertSubject("", "")
	Error("tracer failed to attach a probe")
	if a := nextAlert(t, got); a["pod"] != "" || a["namespace"] != "" {
		t.Errorf("alert pod=%v namespace=%v, want neither", a["pod"], a["namespace"])
	}
}
