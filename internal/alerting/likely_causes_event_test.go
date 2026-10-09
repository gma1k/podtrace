package alerting

import (
	"testing"
	"time"
)

func issueAlert(causes []string) *Alert {
	a := &Alert{
		Source: AlertSourceIssue, Severity: SeverityWarning, Namespace: "shop", PodName: "front-0",
		Title: "Degraded request latency for shop/front", ErrorCode: "l7.latency_degraded",
		Context: map[string]interface{}{"workload": "front"},
	}
	if causes != nil {
		a.Context["likely_causes"] = causes
	}
	return a
}

func TestAnIssuesEventNamesItsLikelyCauses(t *testing.T) {
	ev := BuildAlertEvent(issueAlert([]string{"db.pool_saturated on shop/backend", "cpu.contention on shop/front"}), time.Now())
	want := "Degraded request latency for shop/front. Likely cause: db.pool_saturated on shop/backend; cpu.contention on shop/front"
	if ev.Message != want {
		t.Errorf("message %q, want %q", ev.Message, want)
	}
	if got := ev.Annotations[AnnotationLikelyCauses]; got != "db.pool_saturated on shop/backend; cpu.contention on shop/front" {
		t.Errorf("annotation %q", got)
	}
	if ev.Annotations[AnnotationIssueID] != "l7.latency_degraded" {
		t.Errorf("the issue id annotation the trigger matches on is %q", ev.Annotations[AnnotationIssueID])
	}
}

func TestAnIssueWithoutCausesWritesTheEventAsBefore(t *testing.T) {
	for _, causes := range [][]string{nil, {}} {
		ev := BuildAlertEvent(issueAlert(causes), time.Now())
		if ev.Message != "Degraded request latency for shop/front" {
			t.Errorf("message %q", ev.Message)
		}
		if _, ok := ev.Annotations[AnnotationLikelyCauses]; ok {
			t.Errorf("annotation present without causes: %v", ev.Annotations)
		}
	}
}

func TestOnlyAnIssueAlertCarriesLikelyCauses(t *testing.T) {
	a := issueAlert([]string{"db.pool_saturated on shop/backend"})
	a.Source = AlertSourceOOM
	ev := BuildAlertEvent(a, time.Now())
	if ev.Message != a.Title {
		t.Errorf("message %q, want the title", ev.Message)
	}
	if _, ok := ev.Annotations[AnnotationLikelyCauses]; ok {
		t.Errorf("an OOM alert carries likely causes: %v", ev.Annotations)
	}
}
