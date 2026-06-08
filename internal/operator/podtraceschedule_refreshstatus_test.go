package operator

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func TestRefreshStatus_ActiveAndLastSuccess(t *testing.T) {
	r := &PodTraceScheduleReconciler{}

	sch := &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{Name: "sch", Namespace: "team-a", Generation: 9},
	}

	active := []podtracev1alpha1.PodTraceSession{
		{ObjectMeta: metav1.ObjectMeta{Name: "z-sess", Namespace: "team-a", UID: types.UID("u-z"), ResourceVersion: "10"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "a-sess", Namespace: "team-a", UID: types.UID("u-a"), ResourceVersion: "11"}},
	}
	last := metav1.NewTime(time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC))

	r.refreshStatus(sch, active, &last)

	if len(sch.Status.Active) != 2 {
		t.Fatalf("Active len=%d want 2", len(sch.Status.Active))
	}
	if sch.Status.Active[0].Name != "a-sess" || sch.Status.Active[1].Name != "z-sess" {
		t.Errorf("Active not sorted by name: %v", []string{sch.Status.Active[0].Name, sch.Status.Active[1].Name})
	}
	if sch.Status.Active[0].Kind != "PodTraceSession" {
		t.Errorf("Active[0].Kind=%q want PodTraceSession", sch.Status.Active[0].Kind)
	}
	if sch.Status.Active[0].UID != types.UID("u-a") {
		t.Errorf("Active[0].UID=%q want u-a", sch.Status.Active[0].UID)
	}
	if sch.Status.LastSuccessfulTime == nil || !sch.Status.LastSuccessfulTime.Equal(&last) {
		t.Errorf("LastSuccessfulTime=%v want %v", sch.Status.LastSuccessfulTime, last)
	}
	if sch.Status.ObservedGeneration != 9 {
		t.Errorf("ObservedGeneration=%d want 9", sch.Status.ObservedGeneration)
	}
}

func TestRefreshStatus_NoActiveNoLastSuccess(t *testing.T) {
	r := &PodTraceScheduleReconciler{}
	sch := &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{Name: "sch", Generation: 3},
	}
	r.refreshStatus(sch, nil, nil)
	if len(sch.Status.Active) != 0 {
		t.Errorf("Active should be empty, got %d", len(sch.Status.Active))
	}
	if sch.Status.LastSuccessfulTime != nil {
		t.Errorf("LastSuccessfulTime should stay nil when lastSuccess is nil")
	}
	if sch.Status.ObservedGeneration != 3 {
		t.Errorf("ObservedGeneration=%d want 3", sch.Status.ObservedGeneration)
	}
}
