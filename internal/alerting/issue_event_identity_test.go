package alerting

import (
	"testing"
	"time"
)

func TestAnIssueEventNamesItsIssueAndWorkload(t *testing.T) {
	ev := BuildAlertEvent(&Alert{
		Source:    AlertSourceIssue,
		Namespace: "shop",
		PodName:   "checkout-7d9f",
		ErrorCode: "l7.error_rate",
		Context:   map[string]interface{}{"workload": "checkout"},
	}, time.Now())

	if got := ev.Annotations[AnnotationIssueID]; got != "l7.error_rate" {
		t.Errorf("%s = %q; without it the Event cannot be tied back to the issue it reports", AnnotationIssueID, got)
	}
	if got := ev.Annotations[AnnotationWorkload]; got != "checkout" {
		t.Errorf("%s = %q; a workload-level issue names no pod, so the workload is the only link", AnnotationWorkload, got)
	}
}

func TestOnlyIssueEventsCarryTheIssueIdentity(t *testing.T) {
	ev := BuildAlertEvent(&Alert{
		Source:    AlertSourceResourceMonitor,
		Namespace: "shop",
		PodName:   "checkout-7d9f",
		ErrorCode: "cpu",
		Context:   map[string]interface{}{"workload": "checkout"},
	}, time.Now())
	for _, key := range []string{AnnotationIssueID, AnnotationWorkload} {
		if _, ok := ev.Annotations[key]; ok {
			t.Errorf("a resource alert carries %s", key)
		}
	}
}

func TestAnIssueEventWithoutAWorkloadStillNamesTheIssue(t *testing.T) {
	ev := BuildAlertEvent(&Alert{
		Source:    AlertSourceIssue,
		Namespace: "shop",
		PodName:   "checkout-7d9f",
		ErrorCode: "resource.saturation",
		Context:   map[string]interface{}{"workload": 42},
	}, time.Now())
	if _, ok := ev.Annotations[AnnotationWorkload]; ok {
		t.Error("a non-string workload was written as an annotation")
	}
	if ev.Annotations[AnnotationIssueID] != "resource.saturation" {
		t.Error("the issue id was dropped")
	}
	bare := BuildAlertEvent(&Alert{Source: AlertSourceIssue, Namespace: "shop", PodName: "p"}, time.Now())
	if _, ok := bare.Annotations[AnnotationIssueID]; ok {
		t.Error("an empty issue id was written as an annotation")
	}
}
