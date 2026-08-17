package operator

import (
	"context"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestScheduleReconcile_InvalidTemplateMetadataFailsTerminally(t *testing.T) {
	sch := &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "bad-template",
			Namespace:         "default",
			UID:               "sch-bad",
			Generation:        1,
			CreationTimestamp: metav1.NewTime(fixedScheduleNow.Add(-6 * time.Minute)),
		},
		Spec: podtracev1alpha1.PodTraceScheduleSpec{
			Schedule: "*/5 * * * *",
			SessionTemplate: podtracev1alpha1.PodTraceSessionTemplateSpec{
				Metadata: podtracev1alpha1.PodTraceSessionTemplateMetadata{
					Labels: map[string]string{"team": "not a valid value"},
				},
				Spec: podtracev1alpha1.PodTraceSessionSpec{},
			},
		},
	}

	r, _ := newScheduleReconciler(t, sch)
	ctx := context.Background()

	res, err := r.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Name: sch.Name, Namespace: sch.Namespace},
	})
	if err != nil {
		t.Fatalf("terminal validation failure must not return an error, got %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Fatalf("an invalid template must not requeue, got %v", res.RequeueAfter)
	}

	var sessions podtracev1alpha1.PodTraceSessionList
	if err := r.List(ctx, &sessions, client.InNamespace(sch.Namespace)); err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(sessions.Items) != 0 {
		t.Fatalf("no child session should be created from an invalid template, got %d", len(sessions.Items))
	}

	var got podtracev1alpha1.PodTraceSchedule
	if err := r.Get(ctx, types.NamespacedName{Name: sch.Name, Namespace: sch.Namespace}, &got); err != nil {
		t.Fatalf("get schedule: %v", err)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, ConditionDegraded)
	if cond == nil || cond.Reason != "SessionTemplateInvalid" {
		t.Fatalf("degraded condition = %+v, want reason SessionTemplateInvalid", cond)
	}
}
