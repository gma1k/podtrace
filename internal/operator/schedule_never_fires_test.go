package operator

import (
	"context"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func neverFiringSchedule() *podtracev1alpha1.PodTraceSchedule {
	return &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{
			Name: "feb30", Namespace: "default", UID: "feb30-uid",
			CreationTimestamp: metav1.NewTime(fixedScheduleNow.Add(-time.Hour)),
		},
		Spec: podtracev1alpha1.PodTraceScheduleSpec{Schedule: "0 0 30 2 *"},
	}
}

func TestScheduleReconcile_NeverFiringScheduleSettles(t *testing.T) {
	r, _ := newScheduleReconciler(t, neverFiringSchedule())
	clock := fixedScheduleNow
	r.nowFn = func() time.Time { return clock }
	ctx := context.Background()
	key := types.NamespacedName{Name: "feb30", Namespace: "default"}

	statuses := make([]podtracev1alpha1.PodTraceScheduleStatus, 0, 3)
	for range 3 {
		res, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key})
		if err != nil {
			t.Fatalf("reconcile: %v", err)
		}
		if res != (ctrl.Result{}) {
			t.Fatalf("result = %+v, want no requeue for a schedule that never fires", res)
		}
		var got podtracev1alpha1.PodTraceSchedule
		if err := r.Get(ctx, key, &got); err != nil {
			t.Fatal(err)
		}
		statuses = append(statuses, got.Status)
		clock = clock.Add(time.Second)
	}
	if !equality.Semantic.DeepEqual(statuses[1], statuses[2]) {
		t.Fatalf("status changed between passes, so every write re-enqueues the schedule:\n%+v\n%+v", statuses[1], statuses[2])
	}

	var got podtracev1alpha1.PodTraceSchedule
	if err := r.Get(ctx, key, &got); err != nil {
		t.Fatal(err)
	}
	cond := findCondition(got.Status.Conditions, ConditionDegraded)
	if cond == nil || cond.Reason != "ScheduleInvalid" {
		t.Fatalf("Degraded = %+v, want ScheduleInvalid", cond)
	}
	if got.Status.LastScheduleTime != nil {
		t.Errorf("lastScheduleTime = %v, want unset for a schedule that never ran", got.Status.LastScheduleTime)
	}
	var sessions podtracev1alpha1.PodTraceSessionList
	if err := r.List(ctx, &sessions); err != nil {
		t.Fatal(err)
	}
	if len(sessions.Items) != 0 {
		t.Errorf("%d session(s) created for a schedule that never fires", len(sessions.Items))
	}
}
