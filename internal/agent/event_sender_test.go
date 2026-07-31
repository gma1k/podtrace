package agent

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/podtrace/podtrace/internal/alerting"
)

func newFakeClient() client.Client {
	return fake.NewClientBuilder().Build()
}

func countEvents(t *testing.T, c client.Client) int {
	t.Helper()
	var list corev1.EventList
	if err := c.List(context.Background(), &list); err != nil {
		t.Fatalf("list events: %v", err)
	}
	return len(list.Items)
}

func TestAlertEventSender_SkipsAlertWithoutPod(t *testing.T) {
	c := newFakeClient()
	s := newAlertEventSender(c)
	alert := &alerting.Alert{Severity: alerting.SeverityFatal, Source: alerting.AlertSourceResourceMonitor, Title: "t"}
	if err := s.Send(context.Background(), alert); err != nil {
		t.Fatalf("send: %v", err)
	}
	if n := countEvents(t, c); n != 0 {
		t.Errorf("expected no Event for pod-less alert, got %d", n)
	}
}

func TestAlertEventSender_EmitsEventForPodAlert(t *testing.T) {
	c := newFakeClient()
	s := newAlertEventSender(c)
	alert := &alerting.Alert{
		Severity:  alerting.SeverityCritical,
		Source:    alerting.AlertSourceOOM,
		Title:     "OOM killed",
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
		t.Fatalf("expected 1 Event, got %d", len(list.Items))
	}
	ev := list.Items[0]
	if ev.Reason != alerting.EventReasonAlert ||
		ev.InvolvedObject.Name != "checkout-7f" ||
		ev.InvolvedObject.Namespace != "prod" ||
		ev.Annotations[alerting.AnnotationAlertSource] != alerting.AlertSourceOOM ||
		ev.Annotations[alerting.AnnotationAlertSeverity] != string(alerting.SeverityCritical) {
		t.Errorf("unexpected Event: %+v", ev)
	}
}

func TestAlertEventSender_ThrottlesDuplicates(t *testing.T) {
	c := newFakeClient()
	s := newAlertEventSender(c)
	base := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	s.nowFn = func() time.Time { return base }
	alert := &alerting.Alert{Severity: alerting.SeverityFatal, Source: alerting.AlertSourceOOM, Title: "x", PodName: "p", Namespace: "ns"}

	_ = s.Send(context.Background(), alert)
	_ = s.Send(context.Background(), alert)
	if n := countEvents(t, c); n != 1 {
		t.Errorf("duplicate within throttle should collapse to 1 Event, got %d", n)
	}

	s.nowFn = func() time.Time { return base.Add(31 * time.Second) }
	_ = s.Send(context.Background(), alert)
	if n := countEvents(t, c); n != 2 {
		t.Errorf("after throttle window a new Event should emit, got %d", n)
	}
}
