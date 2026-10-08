package agent

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/gma1k/podtrace/internal/alerting"
)

func issueAlert(id string) *alerting.Alert {
	return &alerting.Alert{
		Severity:  alerting.SeverityWarning,
		Source:    alerting.AlertSourceIssue,
		Title:     id + " on resolver",
		ErrorCode: id,
		PodName:   "resolver",
		Namespace: "shop",
		Context:   map[string]interface{}{"workload": "resolver"},
	}
}

func TestTwoIssuesOnOnePodEachGetTheirEvent(t *testing.T) {
	c := newFakeClient()
	s := newAlertEventSender(c)
	s.nowFn = func() time.Time { return time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC) }

	for _, id := range []string{"dns.failure_rate", "dns.slow_lookup_rate", "dns.failure_rate"} {
		if err := s.Send(context.Background(), issueAlert(id)); err != nil {
			t.Fatal(err)
		}
	}

	var list corev1.EventList
	if err := c.List(context.Background(), &list); err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, e := range list.Items {
		got[e.Annotations[alerting.AnnotationIssueID]]++
	}
	if got["dns.failure_rate"] != 1 || got["dns.slow_lookup_rate"] != 1 {
		t.Errorf("events by issue %v: a second issue activating on the same pod lost its Event, "+
			"so no schedule selecting it starts a session", got)
	}
}
