package report

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/diagnose/detector"
	"github.com/gma1k/podtrace/internal/events"
)

type sourcedDiagnostician struct {
	mockDiagnostician
	pod, namespace string
}

func (s *sourcedDiagnostician) SourcePod() string       { return s.pod }
func (s *sourcedDiagnostician) SourceNamespace() string { return s.namespace }

func failingConnectEvents() []*events.Event {
	var evts []*events.Event
	for i := 0; i < 10; i++ {
		evts = append(evts, &events.Event{Type: events.EventConnect, Error: 1})
	}
	return evts
}

func capturingAlertManager(t *testing.T) <-chan map[string]any {
	t.Helper()
	got := make(chan map[string]any, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		_ = json.NewDecoder(r.Body).Decode(&payload)
		got <- payload
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	origEnabled, origWebhook, origSlack := config.AlertingEnabled, config.AlertWebhookURL, config.AlertSlackWebhookURL
	t.Cleanup(func() {
		config.AlertingEnabled, config.AlertWebhookURL, config.AlertSlackWebhookURL = origEnabled, origWebhook, origSlack
	})
	config.AlertingEnabled, config.AlertWebhookURL, config.AlertSlackWebhookURL = true, srv.URL, ""

	m, err := alerting.NewManager()
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if !m.IsEnabled() {
		t.Skip("manager not enabled")
	}
	orig := alerting.GetGlobalManager()
	alerting.SetGlobalManager(m)
	t.Cleanup(func() {
		alerting.SetGlobalManager(orig)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = m.Shutdown(ctx)
	})
	return got
}

func TestAnIssueAlertFromAReportNamesTheDiagnosedPod(t *testing.T) {
	got := capturingAlertManager(t)
	d := &sourcedDiagnostician{
		mockDiagnostician: mockDiagnostician{events: failingConnectEvents(), rttSpikeThreshold: 1000},
		pod:               "checkout-7d9f",
		namespace:         "shop",
	}
	if GenerateIssuesSection(d) == "" {
		t.Fatal("no issues detected")
	}
	select {
	case payload := <-got:
		if payload["pod"] != "checkout-7d9f" || payload["namespace"] != "shop" {
			t.Errorf("alert pod=%v namespace=%v, want checkout-7d9f/shop", payload["pod"], payload["namespace"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no alert delivered")
	}
}

func TestAlertSubjectFallsBackToTheIssueWhenTheDiagnosticianDoesNotKnow(t *testing.T) {
	issue := detector.Issue{Subject: detector.Subject{Pod: "from-issue", Namespace: "issue-ns"}}
	if pod, ns := alertSubject(&mockDiagnostician{}, issue); pod != "from-issue" || ns != "issue-ns" {
		t.Errorf("alertSubject = %q/%q, want the issue's subject", pod, ns)
	}
	if pod, ns := alertSubject(&sourcedDiagnostician{}, issue); pod != "from-issue" || ns != "issue-ns" {
		t.Errorf("alertSubject = %q/%q, want the issue's subject when the source is empty", pod, ns)
	}
	if pod, ns := alertSubject(&sourcedDiagnostician{pod: "p", namespace: "n"}, issue); pod != "p" || ns != "n" {
		t.Errorf("alertSubject = %q/%q, want the diagnosed pod", pod, ns)
	}
}

func TestTheRTTSpikeLabelShowsTheThresholdSpikesAreCountedAgainst(t *testing.T) {
	for _, tc := range []struct {
		threshold float64
		label     string
		spikes    int
	}{
		{25, "RTT spikes (>25ms): 2", 2},
		{12.5, "RTT spikes (>12.5ms): 2", 2},
		{100, "RTT spikes (>100ms): 0", 0},
	} {
		d := &mockDiagnostician{
			rttSpikeThreshold: tc.threshold,
			events: []*events.Event{
				{Type: events.EventTCPSend, LatencyNS: 5_000_000},
				{Type: events.EventTCPSend, LatencyNS: 30_000_000},
				{Type: events.EventTCPRecv, LatencyNS: 50_000_000},
			},
		}
		got := GenerateTCPSection(d, time.Second)
		if !strings.Contains(got, tc.label) {
			t.Errorf("threshold %v: section = %q, want %q", tc.threshold, got, tc.label)
		}
	}
}

func TestTheIssuesSectionIsHeadedWithoutAStatisticsSuffix(t *testing.T) {
	d := &mockDiagnostician{events: failingConnectEvents(), rttSpikeThreshold: 1000}
	got := GenerateIssuesSection(d)
	if !strings.HasPrefix(got, "Potential Issues Detected:\n") || strings.Contains(got, "Detected Statistics") {
		t.Errorf("section = %q, want it headed \"Potential Issues Detected:\"", got)
	}
}
