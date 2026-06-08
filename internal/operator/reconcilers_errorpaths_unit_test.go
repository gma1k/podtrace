package operator

import (
	"context"
	"errors"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
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

// These tests drive the error-return branches of the reconcilers and
// their status helpers — branches a plain fake client can't reach
// because it never fails. controller-runtime's interceptor support lets
// us inject a synthetic error from a single client method while
// delegating every other call to the real underlying WithWatch client.

func errInternal() error {
	return apierrors.NewInternalError(errors.New("synthetic interceptor failure"))
}

func errConflict(resource, name string) error {
	return apierrors.NewConflict(
		schema.GroupResource{Group: "podtrace.io", Resource: resource},
		name,
		errors.New("synthetic conflict"),
	)
}

// ─── PodTraceScheduleReconciler ──────────────────────────────────────

// patchStatus conflict: Status().Update returns Conflict -> patchStatus
// swallows it and returns nil, so the whole Reconcile returns no error.
func TestErrPath_Schedule_PatchStatusConflictSwallowed(t *testing.T) {
	sch := scheduleForErrPaths()
	s := newOperatorScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSchedule{}).
		WithObjects(sch).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(_ context.Context, _ client.Client, _ string, _ client.Object, _ ...client.SubResourceUpdateOption) error {
				return errConflict("podtraceschedules", sch.Name)
			},
		}).
		Build()
	r := &PodTraceScheduleReconciler{Client: c, Scheme: s, nowFn: func() time.Time { return fixedScheduleNow }}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: sch.Name, Namespace: sch.Namespace},
	})
	if err != nil {
		t.Fatalf("conflict on status update must be swallowed, got err=%v", err)
	}
}

// patchStatus non-conflict: Status().Update returns a generic error ->
// patchStatus wraps it -> Reconcile returns the error.
func TestErrPath_Schedule_PatchStatusError(t *testing.T) {
	sch := scheduleForErrPaths()
	s := newOperatorScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSchedule{}).
		WithObjects(sch).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(_ context.Context, _ client.Client, _ string, _ client.Object, _ ...client.SubResourceUpdateOption) error {
				return errInternal()
			},
		}).
		Build()
	r := &PodTraceScheduleReconciler{Client: c, Scheme: s, nowFn: func() time.Time { return fixedScheduleNow }}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: sch.Name, Namespace: sch.Namespace},
	}); err == nil {
		t.Fatal("expected wrapped status-update error from Reconcile")
	}
}

// listOwnedSessions error: List of child sessions fails -> Reconcile
// returns the wrapped error early.
func TestErrPath_Schedule_ListOwnedSessionsError(t *testing.T) {
	sch := scheduleForErrPaths()
	s := newOperatorScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSchedule{}).
		WithObjects(sch).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, list client.ObjectList, _ ...client.ListOption) error {
				if _, ok := list.(*podtracev1alpha1.PodTraceSessionList); ok {
					return errInternal()
				}
				return errInternal()
			},
		}).
		Build()
	r := &PodTraceScheduleReconciler{Client: c, Scheme: s, nowFn: func() time.Time { return fixedScheduleNow }}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: sch.Name, Namespace: sch.Namespace},
	}); err == nil {
		t.Fatal("expected listOwnedSessions error from Reconcile")
	}

	if _, err := r.listOwnedSessions(context.Background(), sch); err == nil {
		t.Fatal("expected listOwnedSessions to surface List error")
	}
}

// gcOldest Delete error: applyHistoryLimits -> gcOldest -> Delete fails
// with a non-NotFound error -> wrapped error returned.
func TestErrPath_Schedule_GcOldestDeleteError(t *testing.T) {
	s := newOperatorScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSchedule{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.DeleteOption) error {
				return errInternal()
			},
		}).
		Build()
	r := &PodTraceScheduleReconciler{Client: c, Scheme: s, nowFn: func() time.Time { return fixedScheduleNow }}

	sessions := []podtracev1alpha1.PodTraceSession{
		completedSession("old", fixedScheduleNow.Add(-2*time.Hour)),
		completedSession("new", fixedScheduleNow.Add(-1*time.Hour)),
	}
	if err := r.gcOldest(context.Background(), sessions, 1); err == nil {
		t.Fatal("expected gcOldest to surface Delete error")
	}
}

// Reconcile Get error: a non-NotFound Get failure must propagate as a
// wrapped error (the NotFound short-circuit is already covered).
func TestErrPath_Schedule_ReconcileGetError(t *testing.T) {
	s := newOperatorScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSchedule{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
				return errInternal()
			},
		}).
		Build()
	r := &PodTraceScheduleReconciler{Client: c, Scheme: s, nowFn: func() time.Time { return fixedScheduleNow }}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "any", Namespace: "default"},
	}); err == nil {
		t.Fatal("expected Get error to propagate from Reconcile")
	}
}

// ─── PodTraceSessionReconciler ───────────────────────────────────────

// Reconcile Get error: non-NotFound Get failure -> wrapped error.
func TestErrPath_Session_ReconcileGetError(t *testing.T) {
	s := newOperatorScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
				return errInternal()
			},
		}).
		Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "any", Namespace: "team-a"},
	}); err == nil {
		t.Fatal("expected Get error to propagate from session Reconcile")
	}
}

// Final Status().Update conflict: a fully-resolving session reaches the
// terminal Status().Update; a Conflict there must requeue (no error).
func TestErrPath_Session_FinalStatusUpdateConflictRequeues(t *testing.T) {
	s := newOperatorScheme(t)
	session := runnableSession()
	pod := runningPod("p1", "team-a", "n1", map[string]string{"a": "b"})
	ec := otlpExporter("ec", "team-a")

	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(session, pod, ec).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(_ context.Context, _ client.Client, _ string, _ client.Object, _ ...client.SubResourceUpdateOption) error {
				return errConflict("podtracesessions", session.Name)
			},
		}).
		Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: session.Name, Namespace: session.Namespace},
	})
	if err != nil {
		t.Fatalf("final status conflict must requeue without error, got %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Fatalf("expected requeue on status conflict, got %+v", res)
	}
}

// Final Status().Update generic error: wrapped and returned.
func TestErrPath_Session_FinalStatusUpdateError(t *testing.T) {
	s := newOperatorScheme(t)
	session := runnableSession()
	pod := runningPod("p1", "team-a", "n1", map[string]string{"a": "b"})
	ec := otlpExporter("ec", "team-a")

	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(session, pod, ec).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(_ context.Context, _ client.Client, _ string, _ client.Object, _ ...client.SubResourceUpdateOption) error {
				return errInternal()
			},
		}).
		Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: session.Name, Namespace: session.Namespace},
	}); err == nil {
		t.Fatal("expected final status-update error from session Reconcile")
	}
}

// nodesAtCapacity List error fans into Reconcile: listing session Jobs
// fails -> Reconcile returns the wrapped error. Requires a TracerConfig
// with a non-zero per-node cap so the capacity branch executes.
func TestErrPath_Session_NodesAtCapacityListError(t *testing.T) {
	s := newOperatorScheme(t)
	session := runnableSession()
	pod := runningPod("p1", "team-a", "n1", map[string]string{"a": "b"})
	ec := otlpExporter("ec", "team-a")
	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       podtracev1alpha1.TracerConfigSpec{MaxConcurrentSessionsPerNode: 1},
	}

	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(session, pod, ec, tc).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*batchv1.JobList); ok {
					return errInternal()
				}
				return cl.List(ctx, list, opts...)
			},
		}).
		Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: session.Name, Namespace: session.Namespace},
	}); err == nil {
		t.Fatal("expected nodesAtCapacity List error from session Reconcile")
	}
}

// ExporterConfig Get error (non-NotFound) inside session Reconcile ->
// wrapped error returned.
func TestErrPath_Session_ExporterGetError(t *testing.T) {
	s := newOperatorScheme(t)
	session := runnableSession()
	pod := runningPod("p1", "team-a", "n1", map[string]string{"a": "b"})

	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(session, pod).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*podtracev1alpha1.ExporterConfig); ok {
					return errInternal()
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		}).
		Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: session.Name, Namespace: session.Namespace},
	}); err == nil {
		t.Fatal("expected ExporterConfig Get error from session Reconcile")
	}
}

// ─── PodTraceReconciler ──────────────────────────────────────────────

// Reconcile Get error: non-NotFound Get -> wrapped error.
func TestErrPath_PodTrace_ReconcileGetError(t *testing.T) {
	s := newOperatorScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
				return errInternal()
			},
		}).
		Build()
	r := &PodTraceReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "any", Namespace: "team-a"},
	}); err == nil {
		t.Fatal("expected Get error to propagate from PodTrace Reconcile")
	}
}

// syncExporterBundle error: the bundle ConfigMap CreateOrUpdate fails ->
// Reconcile records BundleSync degraded and requeues (no error, 60s).
func TestErrPath_PodTrace_SyncExporterBundleError(t *testing.T) {
	s := newOperatorScheme(t)
	pt := podTraceWithFinalizer()
	ec := otlpExporter("ec", "team-a")

	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(pt, ec).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.ConfigMap); ok {
					return errInternal()
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		}).
		Build()
	r := &PodTraceReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: pt.Name, Namespace: pt.Namespace},
	})
	if err != nil {
		t.Fatalf("bundle-sync failure is recorded in status, not returned; got %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Fatalf("expected requeue after bundle-sync failure, got %+v", res)
	}
}

// Final Status().Update conflict on the happy path -> requeue, no error.
func TestErrPath_PodTrace_FinalStatusUpdateConflictRequeues(t *testing.T) {
	s := newOperatorScheme(t)
	pt := podTraceWithFinalizer()
	ec := otlpExporter("ec", "team-a")

	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(pt, ec).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(_ context.Context, _ client.Client, _ string, _ client.Object, _ ...client.SubResourceUpdateOption) error {
				return errConflict("podtraces", pt.Name)
			},
		}).
		Build()
	r := &PodTraceReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: pt.Name, Namespace: pt.Namespace},
	})
	if err != nil {
		t.Fatalf("status conflict must requeue without error, got %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Fatalf("expected requeue on status conflict, got %+v", res)
	}
}

// Final Status().Update generic error -> wrapped error returned.
func TestErrPath_PodTrace_FinalStatusUpdateError(t *testing.T) {
	s := newOperatorScheme(t)
	pt := podTraceWithFinalizer()
	ec := otlpExporter("ec", "team-a")

	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(pt, ec).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(_ context.Context, _ client.Client, _ string, _ client.Object, _ ...client.SubResourceUpdateOption) error {
				return errInternal()
			},
		}).
		Build()
	r := &PodTraceReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: pt.Name, Namespace: pt.Namespace},
	}); err == nil {
		t.Fatal("expected final status-update error from PodTrace Reconcile")
	}
}

// ─── ExporterConfigReconciler ────────────────────────────────────────

// Reconcile Get error: non-NotFound Get -> wrapped error.
func TestErrPath_ExporterConfig_ReconcileGetError(t *testing.T) {
	s := newOperatorScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.ExporterConfig{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
				return errInternal()
			},
		}).
		Build()
	r := &ExporterConfigReconciler{Client: c, Scheme: s}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "ec", Namespace: "team-a"},
	}); err == nil {
		t.Fatal("expected Get error to propagate from ExporterConfig Reconcile")
	}
}

// Status().Patch conflict: the EC reconciler uses Status().Patch (not
// Update); a Conflict there requeues after 1s with no error.
func TestErrPath_ExporterConfig_StatusPatchConflictRequeues(t *testing.T) {
	s := newOperatorScheme(t)
	ec := otlpExporter("ec", "team-a")
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.ExporterConfig{}).
		WithObjects(ec).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(_ context.Context, _ client.Client, _ string, _ client.Object, _ client.Patch, _ ...client.SubResourcePatchOption) error {
				return errConflict("exporterconfigs", ec.Name)
			},
		}).
		Build()
	r := &ExporterConfigReconciler{Client: c, Scheme: s}

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: ec.Name, Namespace: ec.Namespace},
	})
	if err != nil {
		t.Fatalf("status-patch conflict must requeue without error, got %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Fatalf("expected requeue on status-patch conflict, got %+v", res)
	}
}

// Status().Patch generic error -> wrapped error returned.
func TestErrPath_ExporterConfig_StatusPatchError(t *testing.T) {
	s := newOperatorScheme(t)
	ec := otlpExporter("ec", "team-a")
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.ExporterConfig{}).
		WithObjects(ec).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourcePatch: func(_ context.Context, _ client.Client, _ string, _ client.Object, _ client.Patch, _ ...client.SubResourcePatchOption) error {
				return errInternal()
			},
		}).
		Build()
	r := &ExporterConfigReconciler{Client: c, Scheme: s}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: ec.Name, Namespace: ec.Namespace},
	}); err == nil {
		t.Fatal("expected status-patch error from ExporterConfig Reconcile")
	}
}

// ─── ApplicationTraceReconciler ──────────────────────────────────────

// patchStatus conflict (the 40%-covered helper): Status().Update returns
// Conflict -> patchStatus swallows -> Reconcile returns no error.
func TestErrPath_ApplicationTrace_PatchStatusConflictSwallowed(t *testing.T) {
	s := newOperatorScheme(t)
	app := mkApp()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.ApplicationTrace{}, &podtracev1alpha1.PodTrace{}).
		WithObjects(app).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(_ context.Context, _ client.Client, _ string, _ client.Object, _ ...client.SubResourceUpdateOption) error {
				return errConflict("applicationtraces", app.Name)
			},
		}).
		Build()
	r := &ApplicationTraceReconciler{Client: c, Scheme: s}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: app.Name, Namespace: app.Namespace},
	}); err != nil {
		t.Fatalf("conflict on status update must be swallowed, got err=%v", err)
	}
}

// patchStatus generic error -> wrapped error from Reconcile.
func TestErrPath_ApplicationTrace_PatchStatusError(t *testing.T) {
	s := newOperatorScheme(t)
	app := mkApp()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.ApplicationTrace{}, &podtracev1alpha1.PodTrace{}).
		WithObjects(app).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(_ context.Context, _ client.Client, _ string, _ client.Object, _ ...client.SubResourceUpdateOption) error {
				return errInternal()
			},
		}).
		Build()
	r := &ApplicationTraceReconciler{Client: c, Scheme: s}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: app.Name, Namespace: app.Namespace},
	}); err == nil {
		t.Fatal("expected wrapped status-update error from ApplicationTrace Reconcile")
	}
}

// Reconcile Get error: non-NotFound Get -> wrapped error.
func TestErrPath_ApplicationTrace_ReconcileGetError(t *testing.T) {
	s := newOperatorScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.ApplicationTrace{}, &podtracev1alpha1.PodTrace{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
				return errInternal()
			},
		}).
		Build()
	r := &ApplicationTraceReconciler{Client: c, Scheme: s}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "shop", Namespace: "demo"},
	}); err == nil {
		t.Fatal("expected Get error to propagate from ApplicationTrace Reconcile")
	}
}

// ensureChildPodTrace error path: the child-PodTrace CreateOrUpdate fails
// -> Reconcile sets ChildPodTrace degraded, patches status, then returns
// the original error.
func TestErrPath_ApplicationTrace_EnsureChildError(t *testing.T) {
	s := newOperatorScheme(t)
	app := mkApp()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.ApplicationTrace{}, &podtracev1alpha1.PodTrace{}).
		WithObjects(app).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*podtracev1alpha1.PodTrace); ok {
					return errInternal()
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		}).
		Build()
	r := &ApplicationTraceReconciler{Client: c, Scheme: s}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: app.Name, Namespace: app.Namespace},
	}); err == nil {
		t.Fatal("expected ensureChildPodTrace error from ApplicationTrace Reconcile")
	}
}

// ─── TracerConfigReconciler ──────────────────────────────────────────

// Reconcile Get error: non-NotFound Get -> wrapped error.
func TestErrPath_TracerConfig_ReconcileGetError(t *testing.T) {
	s := newOperatorScheme(t)
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.TracerConfig{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
				return errInternal()
			},
		}).
		Build()
	r := &TracerConfigReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "default"},
	}); err == nil {
		t.Fatal("expected Get error to propagate from TracerConfig Reconcile")
	}
}

// ensureAgentRBAC error: the first Create (ServiceAccount) fails ->
// Reconcile sets RBACError degraded and returns the error.
func TestErrPath_TracerConfig_RBACCreateError(t *testing.T) {
	s := newOperatorScheme(t)
	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Generation: 1},
		Spec:       podtracev1alpha1.TracerConfigSpec{SystemNamespace: "podtrace-system"},
	}
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.TracerConfig{}).
		WithObjects(tc).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.CreateOption) error {
				if _, ok := obj.(*corev1.ServiceAccount); ok {
					return errInternal()
				}
				return errInternal()
			},
		}).
		Build()
	r := &TracerConfigReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "default"},
	}); err == nil {
		t.Fatal("expected RBAC create error from TracerConfig Reconcile")
	}
}

// ensureAgentDaemonSet error: RBAC succeeds, but the DaemonSet Create
// fails -> DaemonSetError degraded and error returned.
func TestErrPath_TracerConfig_DaemonSetCreateError(t *testing.T) {
	s := newOperatorScheme(t)
	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Generation: 1},
		Spec:       podtracev1alpha1.TracerConfigSpec{SystemNamespace: "podtrace-system"},
	}
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.TracerConfig{}).
		WithObjects(tc).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if _, ok := obj.(*appsv1.DaemonSet); ok {
					return errInternal()
				}
				return cl.Create(ctx, obj, opts...)
			},
		}).
		Build()
	r := &TracerConfigReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "default"},
	}); err == nil {
		t.Fatal("expected DaemonSet create error from TracerConfig Reconcile")
	}
}

// ensureAgentDaemonSet conflict: a Conflict from the DaemonSet
// CreateOrUpdate requeues silently (no error). We inject the conflict on
// the DaemonSet Create so RBAC creation still succeeds first.
func TestErrPath_TracerConfig_DaemonSetConflictRequeues(t *testing.T) {
	s := newOperatorScheme(t)
	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Generation: 1},
		Spec:       podtracev1alpha1.TracerConfigSpec{SystemNamespace: "podtrace-system"},
	}
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.TracerConfig{}).
		WithObjects(tc).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if _, ok := obj.(*appsv1.DaemonSet); ok {
					return errConflict("daemonsets", AgentDaemonSetName())
				}
				return cl.Create(ctx, obj, opts...)
			},
		}).
		Build()
	r := &TracerConfigReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "default"},
	})
	if err != nil {
		t.Fatalf("DaemonSet conflict must requeue without error, got %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Fatalf("expected requeue on DaemonSet conflict, got %+v", res)
	}
}

// Final Status().Update conflict: RBAC + DaemonSet succeed, the terminal
// status update conflicts -> requeue, no error.
func TestErrPath_TracerConfig_FinalStatusUpdateConflictRequeues(t *testing.T) {
	s := newOperatorScheme(t)
	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Generation: 1},
		Spec:       podtracev1alpha1.TracerConfigSpec{SystemNamespace: "podtrace-system"},
	}
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.TracerConfig{}).
		WithObjects(tc).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(_ context.Context, _ client.Client, _ string, _ client.Object, _ ...client.SubResourceUpdateOption) error {
				return errConflict("tracerconfigs", tc.Name)
			},
		}).
		Build()
	r := &TracerConfigReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "default"},
	})
	if err != nil {
		t.Fatalf("final status conflict must requeue without error, got %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Fatalf("expected requeue on status conflict, got %+v", res)
	}
}

// Final Status().Update generic error -> wrapped error returned.
func TestErrPath_TracerConfig_FinalStatusUpdateError(t *testing.T) {
	s := newOperatorScheme(t)
	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Generation: 1},
		Spec:       podtracev1alpha1.TracerConfigSpec{SystemNamespace: "podtrace-system"},
	}
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.TracerConfig{}).
		WithObjects(tc).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(_ context.Context, _ client.Client, _ string, _ client.Object, _ ...client.SubResourceUpdateOption) error {
				return errInternal()
			},
		}).
		Build()
	r := &TracerConfigReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "default"},
	}); err == nil {
		t.Fatal("expected final status-update error from TracerConfig Reconcile")
	}
}

// ─── shared builders for these error-path tests ──────────────────────

// scheduleForErrPaths returns a valid schedule that, with fixedScheduleNow,
// reaches the create-session + patchStatus path of Reconcile.
func scheduleForErrPaths() *podtracev1alpha1.PodTraceSchedule {
	return &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "every5",
			Namespace:         "default",
			UID:               "sch-err-uid",
			Generation:        3,
			CreationTimestamp: metav1.NewTime(fixedScheduleNow.Add(-24 * time.Hour)),
		},
		Spec: podtracev1alpha1.PodTraceScheduleSpec{
			Schedule: "*/5 * * * *",
			SessionTemplate: podtracev1alpha1.PodTraceSessionTemplateSpec{
				Spec: podtracev1alpha1.PodTraceSessionSpec{},
			},
		},
	}
}

func completedSession(name string, completedAt time.Time) podtracev1alpha1.PodTraceSession {
	ct := metav1.NewTime(completedAt)
	return podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Status: podtracev1alpha1.PodTraceSessionStatus{
			State:          podtracev1alpha1.SessionStateCompleted,
			CompletionTime: &ct,
		},
	}
}

// runnableSession returns a session past the finalizer-set requeue (the
// cleanup finalizer is already present) so Reconcile proceeds to the
// fan-out and final status update.
func runnableSession() *podtracev1alpha1.PodTraceSession {
	return &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "sess",
			Namespace:  "team-a",
			UID:        "sess-uid",
			Generation: 1,
			Finalizers: []string{FinalizerCleanup},
		},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			Duration:    metav1.Duration{Duration: time.Minute},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec"},
		},
	}
}

func runningPod(name, ns, node string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		Spec:       corev1.PodSpec{NodeName: node},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func otlpExporter(name, ns string) *podtracev1alpha1.ExporterConfig {
	return &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Generation: 1},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "otel:4318", Protocol: podtracev1alpha1.OTLPProtocolHTTP},
		},
	}
}

// podTraceWithFinalizer returns a PodTrace past the finalizer-set
// requeue so Reconcile proceeds to syncExporterBundle + status update.
func podTraceWithFinalizer() *podtracev1alpha1.PodTrace {
	return &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "pt",
			Namespace:  "team-a",
			UID:        "pt-uid",
			Generation: 1,
			Finalizers: []string{FinalizerCleanup},
		},
		Spec: podtracev1alpha1.PodTraceSpec{
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec"},
		},
	}
}
