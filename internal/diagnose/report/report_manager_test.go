package report

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/alerting"
	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
)

// TestGenerateIssuesSection_WithGlobalManager covers the `if manager != nil { ... }` block
// in GenerateIssuesSection (lines 489-515 in report.go) by setting a non-nil global manager.
func TestGenerateIssuesSection_WithGlobalManager(t *testing.T) {
	// Start a fake webhook server so NewManager creates a real enabled manager.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	origEnabled := config.AlertingEnabled
	origWebhook := config.AlertWebhookURL
	origSlack := config.AlertSlackWebhookURL
	t.Cleanup(func() {
		config.AlertingEnabled = origEnabled
		config.AlertWebhookURL = origWebhook
		config.AlertSlackWebhookURL = origSlack
	})
	config.AlertingEnabled = true
	config.AlertWebhookURL = srv.URL
	config.AlertSlackWebhookURL = ""

	m, err := alerting.NewManager()
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}
	if !m.IsEnabled() {
		t.Skip("manager not enabled (sender construction failed)")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = m.Shutdown(ctx)
	})

	orig := alerting.GetGlobalManager()
	alerting.SetGlobalManager(m)
	defer alerting.SetGlobalManager(orig)

	// 10 connect events with errors → 100% error rate > 0% threshold → issues detected.
	var evts []*events.Event
	for i := 0; i < 10; i++ {
		evts = append(evts, &events.Event{Type: events.EventConnect, Error: 1})
	}
	d := &mockDiagnostician{
		events:             evts,
		startTime:          time.Now(),
		endTime:            time.Now().Add(time.Second),
		errorRateThreshold: 0.0,
		rttSpikeThreshold:  1000.0,
	}

	result := GenerateIssuesSection(d)
	if result == "" {
		t.Fatal("expected non-empty issues section")
	}
	if !strings.Contains(result, "failure rate") {
		t.Errorf("expected 'failure rate' in result, got %q", result)
	}
}

// TestGenerateIssuesSection_WithGlobalManager_NoIssues verifies that when there
// are no issues, the manager block is skipped and empty string is returned.
func TestGenerateIssuesSection_WithGlobalManager_NoIssues(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	origEnabled := config.AlertingEnabled
	origWebhook := config.AlertWebhookURL
	origSlack := config.AlertSlackWebhookURL
	t.Cleanup(func() {
		config.AlertingEnabled = origEnabled
		config.AlertWebhookURL = origWebhook
		config.AlertSlackWebhookURL = origSlack
	})
	config.AlertingEnabled = true
	config.AlertWebhookURL = srv.URL
	config.AlertSlackWebhookURL = ""

	m, err := alerting.NewManager()
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}
	if !m.IsEnabled() {
		t.Skip("manager not enabled (sender construction failed)")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = m.Shutdown(ctx)
	})

	orig := alerting.GetGlobalManager()
	alerting.SetGlobalManager(m)
	defer alerting.SetGlobalManager(orig)

	// No events → no issues → return "".
	d := &mockDiagnostician{
		events:             []*events.Event{},
		startTime:          time.Now(),
		endTime:            time.Now().Add(time.Second),
		errorRateThreshold: 10.0,
		rttSpikeThreshold:  1000.0,
	}
	result := GenerateIssuesSection(d)
	if result != "" {
		t.Errorf("expected empty string for no issues, got %q", result)
	}
}
