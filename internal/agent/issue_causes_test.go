package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/diagnose/detector"
	"github.com/gma1k/podtrace/internal/inspect"
)

func latencyCausedByThePool() detector.Issue {
	is := saturationIssue("checkout-abc")
	is.ID = detector.IDL7LatencyDegraded
	is.Message = "Latency degraded for shop/checkout"
	is.Causes = []detector.Cause{{IssueRef: detector.IssueRef{ID: detector.IDDBPoolSaturated, Namespace: "shop", Workload: "checkout"}}}
	return is
}

func TestTheAlertNamesTheLikelyCause(t *testing.T) {
	alerter, sent := newTestAlerter()
	alerter.IssueActivated(latencyCausedByThePool())
	alert := (*sent)[0]
	if want := "Latency degraded for shop/checkout. Likely cause: db.pool_saturated on shop/checkout"; alert.Message != want {
		t.Errorf("message %q, want %q", alert.Message, want)
	}
	if want := []string{"db.pool_saturated on shop/checkout"}; !reflect.DeepEqual(alert.Context["likely_causes"], want) {
		t.Errorf("likely_causes %v, want %v", alert.Context["likely_causes"], want)
	}
}

func TestTheAlertTitleStaysTheSameSoACauseDoesNotReFireIt(t *testing.T) {
	alerter, sent := newTestAlerter()
	plain := latencyCausedByThePool()
	plain.Causes = nil
	alerter.IssueActivated(plain)
	alerter.IssueActivated(latencyCausedByThePool())
	if (*sent)[0].Title != (*sent)[1].Title || (*sent)[0].Key() != (*sent)[1].Key() {
		t.Errorf("titles %q and %q differ, so the deduplicator sees two alerts", (*sent)[0].Title, (*sent)[1].Title)
	}
}

func TestAnIssueWithoutACauseAlertsAsBefore(t *testing.T) {
	alerter, sent := newTestAlerter()
	alerter.IssueActivated(saturationIssue("checkout-abc"))
	alert := (*sent)[0]
	if alert.Message != saturationIssue("").Message {
		t.Errorf("message %q", alert.Message)
	}
	if _, ok := alert.Context["likely_causes"]; ok {
		t.Errorf("likely_causes present without a cause: %v", alert.Context["likely_causes"])
	}
}

type servedFamilies struct{ families []*dto.MetricFamily }

func (s *servedFamilies) Gather() ([]*dto.MetricFamily, error) { return s.families, nil }

func edgeCounter(value float64) *dto.MetricFamily {
	name, kind := "podtrace_workload_edge_requests_total", dto.MetricType_COUNTER
	pair := func(n, v string) *dto.LabelPair { return &dto.LabelPair{Name: &n, Value: &v} }
	return &dto.MetricFamily{Name: &name, Type: &kind, Metric: []*dto.Metric{{
		Label: []*dto.LabelPair{
			pair("namespace", "shop"), pair("workload", "checkout"),
			pair("target_namespace", "shop"), pair("target_service", "payments"), pair("outcome", "ok"),
		},
		Counter: &dto.Counter{Value: &value},
	}}}
}

func TestTheIssuesEndpointServesCausesAndTheWorkloadsCalls(t *testing.T) {
	clock := time.Date(2026, 10, 9, 9, 0, 0, 0, time.UTC)
	fire := func(id detector.ID) inspect.Rule {
		return inspect.Rule{ID: id, Eval: func(inspect.Window, inspect.Thresholds) []detector.Issue {
			return []detector.Issue{{ID: id, Severity: alerting.SeverityWarning, Message: string(id),
				Subject: detector.Subject{Namespace: "shop", Workload: "checkout", Pod: "checkout-0"}}}
		}}
	}
	gatherer := &servedFamilies{families: []*dto.MetricFamily{edgeCounter(1)}}
	engine, err := inspect.New(inspect.Options{
		Gatherer: gatherer, Registerer: prometheus.NewRegistry(),
		Rules: []inspect.Rule{fire(detector.IDL7LatencyDegraded), fire(detector.IDDBPoolSaturated)},
		Now:   func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Evaluate(); err != nil {
		t.Fatal(err)
	}
	gatherer.families, clock = []*dto.MetricFamily{edgeCounter(6)}, clock.Add(30*time.Second)
	if _, err := engine.Evaluate(); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	issuesHandler(engine)(rec, httptest.NewRequest(http.MethodGet, "/issues", nil))
	var body struct {
		Issues []ActiveIssue  `json:"issues"`
		Edges  []inspect.Edge `json:"edges"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	var latency ActiveIssue
	for _, is := range body.Issues {
		if is.ID == string(detector.IDL7LatencyDegraded) {
			latency = is
		}
	}
	if len(latency.Causes) != 1 || latency.Causes[0].ID != detector.IDDBPoolSaturated {
		t.Errorf("latency causes %+v, want the pool", latency.Causes)
	}
	want := []inspect.Edge{{Namespace: "shop", Workload: "checkout", TargetNamespace: "shop", TargetService: "payments", Requests: 5}}
	if !reflect.DeepEqual(body.Edges, want) {
		t.Errorf("edges %+v, want %+v", body.Edges, want)
	}
}

func TestTheIssuesEndpointServesAnEmptyCallListNotNull(t *testing.T) {
	engine, err := inspect.New(inspect.Options{Gatherer: prometheus.NewRegistry(), Registerer: prometheus.NewRegistry(), Rules: []inspect.Rule{}})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	issuesHandler(engine)(rec, httptest.NewRequest(http.MethodGet, "/issues", nil))
	var body map[string]json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if string(body["edges"]) != "[]" {
		t.Errorf("edges %s, want []", body["edges"])
	}
}
