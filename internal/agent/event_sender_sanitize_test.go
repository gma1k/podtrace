package agent

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/gma1k/podtrace/internal/alerting"
)

func TestAlertEventSenderSanitizesWhatItWritesIntoTheEvent(t *testing.T) {
	c := newFakeClient()
	s := newAlertEventSender(c)
	alert := &alerting.Alert{
		Severity:  alerting.SeverityCritical,
		Source:    alerting.AlertSourceIssue,
		Title:     "latency \x1b[31mhigh\x1b[0m\u202e" + strings.Repeat("x", 400),
		ErrorCode: "issue\x07-" + strings.Repeat("y", 100),
		PodName:   "checkout-7f",
		Namespace: "prod",
	}
	if err := s.Send(context.Background(), alert); err != nil {
		t.Fatalf("send: %v", err)
	}
	var list corev1.EventList
	if err := c.List(context.Background(), &list); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("got %d Events, want 1", len(list.Items))
	}
	ev := list.Items[0]
	for _, field := range []string{ev.Message, ev.Annotations[alerting.AnnotationIssueID]} {
		if strings.ContainsAny(field, "\x1b\x07\u202e") {
			t.Errorf("Event carries terminal control runes: %q", field)
		}
	}
	if len(ev.Message) > 256 {
		t.Errorf("Event message is %d bytes; the title must be capped like every other sink caps it", len(ev.Message))
	}
	if got := len(ev.Annotations[alerting.AnnotationIssueID]); got > 64 {
		t.Errorf("issue annotation is %d bytes, want at most 64", got)
	}
}
