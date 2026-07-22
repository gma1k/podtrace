package operator

import (
	"context"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func schBranchOwnerRef(sch *podtracev1alpha1.PodTraceSchedule) []metav1.OwnerReference {
	return []metav1.OwnerReference{{
		APIVersion: podtracev1alpha1.GroupVersion.String(),
		Kind:       "PodTraceSchedule",
		Name:       sch.Name,
		UID:        sch.UID,
	}}
}

func schBranchAt(name string, creation time.Time, mutate func(*podtracev1alpha1.PodTraceSchedule)) *podtracev1alpha1.PodTraceSchedule {
	sch := &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         "default",
			UID:               types.UID(name + "-uid"),
			Generation:        1,
			CreationTimestamp: metav1.NewTime(creation),
		},
		Spec: podtracev1alpha1.PodTraceScheduleSpec{
			Schedule: "*/5 * * * *",
			SessionTemplate: podtracev1alpha1.PodTraceSessionTemplateSpec{
				Spec: podtracev1alpha1.PodTraceSessionSpec{},
			},
		},
	}
	if mutate != nil {
		mutate(sch)
	}
	return sch
}

func schBranchActive(sch *podtracev1alpha1.PodTraceSchedule, name string) *podtracev1alpha1.PodTraceSession {
	return &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       sch.Namespace,
			OwnerReferences: schBranchOwnerRef(sch),
		},
	}
}

func schBranchCompleted(sch *podtracev1alpha1.PodTraceSchedule, name string, at time.Time) *podtracev1alpha1.PodTraceSession {
	ct := metav1.NewTime(at)
	return &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       sch.Namespace,
			OwnerReferences: schBranchOwnerRef(sch),
		},
		Status: podtracev1alpha1.PodTraceSessionStatus{
			State:          podtracev1alpha1.SessionStateCompleted,
			CompletionTime: &ct,
		},
	}
}

func newSchBranchReconciler(t *testing.T, funcs interceptor.Funcs, objs ...client.Object) *PodTraceScheduleReconciler {
	t.Helper()
	s := newOperatorScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSchedule{}).
		WithObjects(objs...).
		WithInterceptorFuncs(funcs).
		Build()
	return &PodTraceScheduleReconciler{Client: c, Scheme: s, nowFn: func() time.Time { return fixedScheduleNow }}
}

func reconcileSchBranch(r *PodTraceScheduleReconciler, sch *podtracev1alpha1.PodTraceSchedule) (ctrl.Result, error) {
	return r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: sch.Name, Namespace: sch.Namespace},
	})
}

var failAllDeletes = interceptor.Funcs{
	Delete: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.DeleteOption) error {
		return errInternal()
	},
}

var failStatusUpdate = interceptor.Funcs{
	SubResourceUpdate: func(_ context.Context, _ client.Client, _ string, _ client.Object, _ ...client.SubResourceUpdateOption) error {
		return errInternal()
	},
}

func TestSchedBranch_SuspendPatchStatusError(t *testing.T) {
	suspend := true
	sch := schBranchAt("suspend-patcherr", fixedScheduleNow, func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.Suspend = &suspend
	})
	r := newSchBranchReconciler(t, failStatusUpdate, sch)
	if _, err := reconcileSchBranch(r, sch); err == nil {
		t.Fatal("suspended schedule with failing status update must return error")
	}
}

func TestSchedBranch_SuspendHistoryGCError(t *testing.T) {
	suspend := true
	limit := int32(0)
	sch := schBranchAt("suspend-gcerr", fixedScheduleNow, func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.Suspend = &suspend
		s.Spec.SuccessfulSessionsHistoryLimit = &limit
	})
	done := schBranchCompleted(sch, "done", fixedScheduleNow.Add(-time.Hour))
	r := newSchBranchReconciler(t, failAllDeletes, sch, done)
	if _, err := reconcileSchBranch(r, sch); err == nil {
		t.Fatal("suspended schedule with failing history GC delete must return error")
	}
}

func TestSchedBranch_SuspendPatchStatusNotFoundSwallowed(t *testing.T) {
	suspend := true
	sch := schBranchAt("suspend-notfound", fixedScheduleNow, func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.Suspend = &suspend
	})
	funcs := interceptor.Funcs{
		SubResourceUpdate: func(_ context.Context, _ client.Client, _ string, _ client.Object, _ ...client.SubResourceUpdateOption) error {
			return apierrors.NewNotFound(schema.GroupResource{Group: "podtrace.io", Resource: "podtraceschedules"}, sch.Name)
		},
	}
	r := newSchBranchReconciler(t, funcs, sch)
	res, err := reconcileSchBranch(r, sch)
	if err != nil {
		t.Fatalf("a NotFound status update means the schedule was deleted; must be swallowed, got %v", err)
	}
	if res.RequeueAfter != scheduleResyncCeiling {
		t.Fatalf("suspended schedule should requeue after ceiling %v, got %v", scheduleResyncCeiling, res.RequeueAfter)
	}
}

func TestSchedBranch_PatchStatusInnerGetError(t *testing.T) {
	suspend := true
	sch := schBranchAt("suspend-geterr", fixedScheduleNow, func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.Suspend = &suspend
	})
	gets := 0
	funcs := interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			gets++
			if gets >= 2 {
				return errInternal()
			}
			return cl.Get(ctx, key, obj, opts...)
		},
	}
	r := newSchBranchReconciler(t, funcs, sch)
	if _, err := reconcileSchBranch(r, sch); err == nil {
		t.Fatal("patchStatus inner Get failure must propagate as error")
	}
}

func TestSchedBranch_InvalidSchedulePatchStatusError(t *testing.T) {
	sch := schBranchAt("invalid-sched", fixedScheduleNow, func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.Schedule = "this is not a cron expression"
	})
	r := newSchBranchReconciler(t, failStatusUpdate, sch)
	if _, err := reconcileSchBranch(r, sch); err == nil {
		t.Fatal("invalid schedule with failing status update must return error")
	}
}

func TestSchedBranch_BeforeNextRunPatchStatusError(t *testing.T) {
	sch := schBranchAt("before-patcherr", fixedScheduleNow, nil)
	r := newSchBranchReconciler(t, failStatusUpdate, sch)
	if _, err := reconcileSchBranch(r, sch); err == nil {
		t.Fatal("not-yet-due schedule with failing status update must return error")
	}
}

func TestSchedBranch_BeforeNextRunHistoryGCError(t *testing.T) {
	limit := int32(0)
	sch := schBranchAt("before-gcerr", fixedScheduleNow, func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.SuccessfulSessionsHistoryLimit = &limit
	})
	done := schBranchCompleted(sch, "done", fixedScheduleNow.Add(-time.Hour))
	r := newSchBranchReconciler(t, failAllDeletes, sch, done)
	if _, err := reconcileSchBranch(r, sch); err == nil {
		t.Fatal("not-yet-due schedule with failing history GC must return error")
	}
}

func TestSchedBranch_MissedDeadlinePatchStatusError(t *testing.T) {
	deadline := int64(1)
	sch := schBranchAt("missed-patcherr", fixedScheduleNow.Add(-10*time.Minute), func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.StartingDeadlineSeconds = &deadline
	})
	r := newSchBranchReconciler(t, failStatusUpdate, sch)
	if _, err := reconcileSchBranch(r, sch); err == nil {
		t.Fatal("missed-deadline schedule with failing status update must return error")
	}
}

func TestSchedBranch_MissedDeadlineHistoryGCError(t *testing.T) {
	deadline := int64(1)
	limit := int32(0)
	sch := schBranchAt("missed-gcerr", fixedScheduleNow.Add(-10*time.Minute), func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.StartingDeadlineSeconds = &deadline
		s.Spec.SuccessfulSessionsHistoryLimit = &limit
	})
	done := schBranchCompleted(sch, "done", fixedScheduleNow.Add(-time.Hour))
	r := newSchBranchReconciler(t, failAllDeletes, sch, done)
	if _, err := reconcileSchBranch(r, sch); err == nil {
		t.Fatal("missed-deadline schedule with failing history GC must return error")
	}
}

func TestSchedBranch_TooManyMissedHistoryGCError(t *testing.T) {
	limit := int32(0)
	sch := schBranchAt("toomany-gcerr", fixedScheduleNow.Add(-24*time.Hour), func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.SuccessfulSessionsHistoryLimit = &limit
	})
	done := schBranchCompleted(sch, "done", fixedScheduleNow.Add(-time.Hour))
	r := newSchBranchReconciler(t, failAllDeletes, sch, done)
	if _, err := reconcileSchBranch(r, sch); err == nil {
		t.Fatal("backlog-skipping schedule with failing history GC must return error")
	}
}

func TestSchedBranch_MaxActivePatchStatusError(t *testing.T) {
	cap := int32(1)
	sch := schBranchAt("maxactive-patcherr", fixedScheduleNow.Add(-6*time.Minute), func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.MaxActiveSessions = &cap
	})
	active := schBranchActive(sch, "running")
	r := newSchBranchReconciler(t, failStatusUpdate, sch, active)
	if _, err := reconcileSchBranch(r, sch); err == nil {
		t.Fatal("at-capacity schedule with failing status update must return error")
	}
}

func TestSchedBranch_MaxActiveHistoryGCError(t *testing.T) {
	cap := int32(1)
	limit := int32(0)
	sch := schBranchAt("maxactive-gcerr", fixedScheduleNow.Add(-6*time.Minute), func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.MaxActiveSessions = &cap
		s.Spec.SuccessfulSessionsHistoryLimit = &limit
	})
	active := schBranchActive(sch, "running")
	done := schBranchCompleted(sch, "done", fixedScheduleNow.Add(-time.Hour))
	r := newSchBranchReconciler(t, failAllDeletes, sch, active, done)
	if _, err := reconcileSchBranch(r, sch); err == nil {
		t.Fatal("at-capacity schedule with failing history GC must return error")
	}
}

func TestSchedBranch_ForbidPatchStatusError(t *testing.T) {
	sch := schBranchAt("forbid-patcherr", fixedScheduleNow.Add(-6*time.Minute), func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.ConcurrencyPolicy = podtracev1alpha1.ForbidConcurrent
	})
	active := schBranchActive(sch, "running")
	r := newSchBranchReconciler(t, failStatusUpdate, sch, active)
	if _, err := reconcileSchBranch(r, sch); err == nil {
		t.Fatal("Forbid schedule with active sessions and failing status update must return error")
	}
}

func TestSchedBranch_ForbidHistoryGCError(t *testing.T) {
	limit := int32(0)
	sch := schBranchAt("forbid-gcerr", fixedScheduleNow.Add(-6*time.Minute), func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.ConcurrencyPolicy = podtracev1alpha1.ForbidConcurrent
		s.Spec.SuccessfulSessionsHistoryLimit = &limit
	})
	active := schBranchActive(sch, "running")
	done := schBranchCompleted(sch, "done", fixedScheduleNow.Add(-time.Hour))
	r := newSchBranchReconciler(t, failAllDeletes, sch, active, done)
	if _, err := reconcileSchBranch(r, sch); err == nil {
		t.Fatal("Forbid schedule with active sessions and failing history GC must return error")
	}
}

func TestSchedBranch_ReplaceDeleteError(t *testing.T) {
	sch := schBranchAt("replace-delerr", fixedScheduleNow.Add(-6*time.Minute), func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.ConcurrencyPolicy = podtracev1alpha1.ReplaceConcurrent
	})
	active := schBranchActive(sch, "running")
	r := newSchBranchReconciler(t, failAllDeletes, sch, active)
	if _, err := reconcileSchBranch(r, sch); err == nil {
		t.Fatal("Replace schedule that fails to delete an active session must return error")
	}
}

func TestSchedBranch_CreateSessionError(t *testing.T) {
	sch := schBranchAt("create-err", fixedScheduleNow.Add(-6*time.Minute), nil)
	funcs := interceptor.Funcs{
		Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if _, ok := obj.(*podtracev1alpha1.PodTraceSession); ok {
				return errInternal()
			}
			return cl.Create(ctx, obj, opts...)
		},
	}
	r := newSchBranchReconciler(t, funcs, sch)
	if _, err := reconcileSchBranch(r, sch); err == nil {
		t.Fatal("failed session creation must surface as a Reconcile error")
	}
	var got podtracev1alpha1.PodTraceSchedule
	if err := r.Get(context.Background(), types.NamespacedName{Name: sch.Name, Namespace: sch.Namespace}, &got); err != nil {
		t.Fatal(err)
	}
	if c := findScheduleCondition(got.Status.Conditions, ConditionDegraded); c == nil || c.Status != metav1.ConditionTrue {
		t.Fatalf("expected Degraded=True after create failure, conditions=%+v", got.Status.Conditions)
	}
}

func TestSchedBranch_CreateSessionErrorAndPatchStatusError(t *testing.T) {
	sch := schBranchAt("create-patcherr", fixedScheduleNow.Add(-6*time.Minute), nil)
	funcs := interceptor.Funcs{
		Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if _, ok := obj.(*podtracev1alpha1.PodTraceSession); ok {
				return errInternal()
			}
			return cl.Create(ctx, obj, opts...)
		},
		SubResourceUpdate: func(_ context.Context, _ client.Client, _ string, _ client.Object, _ ...client.SubResourceUpdateOption) error {
			return errInternal()
		},
	}
	r := newSchBranchReconciler(t, funcs, sch)
	if _, err := reconcileSchBranch(r, sch); err == nil {
		t.Fatal("create failure with failing status update must return error")
	}
}

func TestSchedBranch_FinalPatchStatusError(t *testing.T) {
	sch := schBranchAt("final-patcherr", fixedScheduleNow.Add(-6*time.Minute), nil)
	r := newSchBranchReconciler(t, failStatusUpdate, sch)
	if _, err := reconcileSchBranch(r, sch); err == nil {
		t.Fatal("successful run with failing final status update must return error")
	}
	var sessions podtracev1alpha1.PodTraceSessionList
	if err := r.List(context.Background(), &sessions, client.InNamespace(sch.Namespace)); err != nil {
		t.Fatal(err)
	}
	if len(sessions.Items) != 1 {
		t.Fatalf("session should still be created before the status write fails, got %d", len(sessions.Items))
	}
}

func TestSchedBranch_SecondListError(t *testing.T) {
	sch := schBranchAt("second-list-err", fixedScheduleNow.Add(-6*time.Minute), nil)
	lists := 0
	funcs := interceptor.Funcs{
		List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*podtracev1alpha1.PodTraceSessionList); ok {
				lists++
				if lists >= 2 {
					return errInternal()
				}
			}
			return cl.List(ctx, list, opts...)
		},
	}
	r := newSchBranchReconciler(t, funcs, sch)
	if _, err := reconcileSchBranch(r, sch); err == nil {
		t.Fatal("post-create session re-list failure must return error")
	}
}

func TestSchedBranch_PostCreateHistoryGCError(t *testing.T) {
	limit := int32(0)
	sch := schBranchAt("postcreate-gcerr", fixedScheduleNow.Add(-6*time.Minute), func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.SuccessfulSessionsHistoryLimit = &limit
	})
	done := schBranchCompleted(sch, "done", fixedScheduleNow.Add(-time.Hour))
	r := newSchBranchReconciler(t, failAllDeletes, sch, done)
	if _, err := reconcileSchBranch(r, sch); err == nil {
		t.Fatal("post-create history GC failure must return error")
	}
}

func findScheduleCondition(conds []metav1.Condition, condType string) *metav1.Condition {
	for i := range conds {
		if conds[i].Type == condType {
			return &conds[i]
		}
	}
	return nil
}
