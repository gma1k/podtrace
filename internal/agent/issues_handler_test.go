package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/diagnose/detector"
	"github.com/gma1k/podtrace/internal/inspect"
)

func TestTheIssuesEndpointServesTheLatestMessageAndTheActivationTime(t *testing.T) {
	message := "mostly timeout"
	clock := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	rule := inspect.Rule{ID: detector.IDDNSFailureRate, Query: "x", Eval: func(inspect.Window, inspect.Thresholds) []detector.Issue {
		return []detector.Issue{{
			ID: detector.IDDNSFailureRate, Severity: alerting.SeverityWarning, Message: message,
			Subject: detector.Subject{Namespace: "shop", Workload: "resolver", Pod: "resolver-0"},
		}}
	}}
	engine, err := inspect.New(inspect.Options{
		Gatherer: prometheus.NewRegistry(), Registerer: prometheus.NewRegistry(),
		Rules: []inspect.Rule{rule}, Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	activatedAt := clock
	if _, err := engine.Evaluate(); err != nil {
		t.Fatal(err)
	}
	message, clock = "mostly SERVFAIL", clock.Add(time.Minute)
	if _, err := engine.Evaluate(); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	issuesHandler(engine)(rec, httptest.NewRequest(http.MethodGet, "/issues", nil))
	var body struct {
		Issues []ActiveIssue `json:"issues"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Issues) != 1 {
		t.Fatalf("issues %+v", body.Issues)
	}
	got := body.Issues[0]
	if got.Message != "mostly SERVFAIL" || !got.Since.Equal(activatedAt) || got.Pod != "resolver-0" || got.ID != "dns.failure_rate" {
		t.Errorf("issue %+v, want the latest message, the activation time and the pod", got)
	}
}

func TestTheIssuesEndpointSaysSoWhenInspectionsAreOff(t *testing.T) {
	rec := httptest.NewRecorder()
	issuesHandler(nil)(rec, httptest.NewRequest(http.MethodGet, "/issues", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status %d, want 404 so a reader falls back to the Events", rec.Code)
	}
}
