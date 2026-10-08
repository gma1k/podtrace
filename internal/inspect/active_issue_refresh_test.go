package inspect

import (
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/diagnose/detector"
)

type scripted struct {
	mu    sync.Mutex
	issue detector.Issue
}

func (s *scripted) set(severity alerting.AlertSeverity, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issue.Severity, s.issue.Message = severity, message
}

func (s *scripted) rule() Rule {
	return Rule{ID: detector.IDDNSFailureRate, For: 0, Query: "x", Eval: func(Window, Thresholds) []detector.Issue {
		s.mu.Lock()
		defer s.mu.Unlock()
		return []detector.Issue{s.issue}
	}}
}

func scriptedEngine(t *testing.T, s *scripted, obs *recorder, clock *time.Time) *Engine {
	t.Helper()
	e, err := New(Options{
		Gatherer:   &fixedGatherer{},
		Registerer: prometheus.NewRegistry(),
		Rules:      []Rule{s.rule()},
		Observer:   obs,
		Now:        func() time.Time { return *clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func newScripted() *scripted {
	return &scripted{issue: detector.Issue{
		ID:       detector.IDDNSFailureRate,
		Severity: alerting.SeverityWarning,
		Subject:  detector.Subject{Namespace: "shop", Workload: "resolver", Pod: "resolver-0"},
		Message:  "mostly timeout",
	}}
}

func TestAnActiveIssueCarriesItsLatestMessageAndWhenItActivated(t *testing.T) {
	s, obs := newScripted(), &recorder{}
	clock := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	e := scriptedEngine(t, s, obs, &clock)
	activatedAt := clock
	if _, err := e.Evaluate(); err != nil {
		t.Fatal(err)
	}

	s.set(alerting.SeverityWarning, "mostly SERVFAIL")
	clock = clock.Add(30 * time.Second)
	if _, err := e.Evaluate(); err != nil {
		t.Fatal(err)
	}

	got := e.ActiveIssues()
	if len(got) != 1 || got[0].Message != "mostly SERVFAIL" || !got[0].Since.Equal(activatedAt) {
		t.Fatalf("active %+v, want the latest message and the activation time", got)
	}
	if len(obs.activated) != 1 {
		t.Errorf("observer told %d times; a changed message is not a new activation", len(obs.activated))
	}
}

func TestAnEscalationIsReportedAndADeEscalationIsNot(t *testing.T) {
	s, obs := newScripted(), &recorder{}
	clock := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	e := scriptedEngine(t, s, obs, &clock)
	step := func(severity alerting.AlertSeverity) []detector.Issue {
		s.set(severity, string(severity))
		clock = clock.Add(30 * time.Second)
		activated, err := e.Evaluate()
		if err != nil {
			t.Fatal(err)
		}
		return activated
	}

	step(alerting.SeverityWarning)
	if got := step(alerting.SeverityCritical); len(got) != 1 || got[0].Severity != alerting.SeverityCritical {
		t.Errorf("escalation returned %v, want the critical issue", got)
	}
	if got := step(alerting.SeverityWarning); len(got) != 0 {
		t.Errorf("de-escalation returned %v, want nothing", got)
	}
	if len(obs.activated) != 2 || obs.activated[1].Severity != alerting.SeverityCritical {
		t.Errorf("observer saw %v, want the activation and the escalation: a schedule waiting for critical starts from the escalation", obs.activated)
	}
	if got := e.ActiveIssues(); len(got) != 1 || got[0].Severity != alerting.SeverityWarning {
		t.Errorf("active %+v, want the de-escalated severity", got)
	}
}

func TestActiveIssuesCanBeReadWhileTheEngineEvaluates(t *testing.T) {
	s, obs := newScripted(), &recorder{}
	clock := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	e := scriptedEngine(t, s, obs, &clock)
	if _, err := e.Evaluate(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			_ = e.ActiveIssues()
		}
	}()
	for i := 0; i < 200; i++ {
		if _, err := e.Evaluate(); err != nil {
			t.Fatal(err)
		}
	}
	<-done
}
