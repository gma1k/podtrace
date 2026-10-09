package agent

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gma1k/podtrace/internal/alerting"
)

func issueAlertFor(pod string) *alerting.Alert {
	return &alerting.Alert{
		Severity: alerting.SeverityWarning, Source: alerting.AlertSourceIssue, ErrorCode: "l7.latency_degraded",
		Title: "Degraded request latency", PodName: pod, Namespace: "shop",
	}
}

func TestTheAlertEventCarriesThePodsUIDSoDescribeListsIt(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "front-0", Namespace: "shop", UID: "front-0-uid"}}
	c := fake.NewClientBuilder().WithObjects(pod).Build()
	if err := newAlertEventSender(c).Send(context.Background(), issueAlertFor("front-0")); err != nil {
		t.Fatal(err)
	}
	var list corev1.EventList
	if err := c.List(context.Background(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("%d Events", len(list.Items))
	}
	if ref := list.Items[0].InvolvedObject; ref.UID != "front-0-uid" || ref.APIVersion != "v1" {
		t.Errorf("involved object %+v: kubectl describe matches Events on the pod's UID", ref)
	}
}

func TestAnUnreadablePodStillGetsItsAlertEvent(t *testing.T) {
	c := newFakeClient()
	if err := newAlertEventSender(c).Send(context.Background(), issueAlertFor("gone-0")); err != nil {
		t.Fatal(err)
	}
	if n := countEvents(t, c); n != 1 {
		t.Errorf("%d Events: the Event starts sessions, so it is written even without the UID", n)
	}
}
