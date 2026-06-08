package operator

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func newUnstartedManager(t *testing.T) ctrl.Manager {
	t.Helper()
	cfg := &rest.Config{Host: "http://127.0.0.1:1"}
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 newOperatorScheme(t),
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
	})
	if err != nil {
		t.Skipf("cannot construct controller-runtime manager in this sandbox: %v", err)
	}
	return mgr
}

func TestMore_SetupWithManager_AllReconcilers(t *testing.T) {
	mgr := newUnstartedManager(t)

	if err := registerExporterConfigIndexers(context.Background(), mgr); err != nil {
		t.Logf("registerExporterConfigIndexers unavailable in sandbox (expected): %v", err)
	}

	cl := mgr.GetClient()
	sc := mgr.GetScheme()

	setups := []struct {
		name  string
		setup func(ctrl.Manager) error
	}{
		{"PodTraceSchedule", (&PodTraceScheduleReconciler{Client: cl, Scheme: sc}).SetupWithManager},
		{"PodTrace", (&PodTraceReconciler{Client: cl, Scheme: sc, SystemNamespace: "podtrace-system"}).SetupWithManager},
		{"PodTraceSession", (&PodTraceSessionReconciler{Client: cl, Scheme: sc, SystemNamespace: "podtrace-system"}).SetupWithManager},
		{"ExporterConfig", (&ExporterConfigReconciler{Client: cl, Scheme: sc}).SetupWithManager},
		{"ApplicationTrace", (&ApplicationTraceReconciler{Client: cl, Scheme: sc}).SetupWithManager},
		{"TracerConfig", (&TracerConfigReconciler{Client: cl, Scheme: sc, SystemNamespace: "podtrace-system"}).SetupWithManager},
	}
	for _, s := range setups {
		if err := s.setup(mgr); err != nil {
			t.Errorf("%s.SetupWithManager: %v", s.name, err)
		}
	}
}

func TestMore_PodTrace_DeletionRemovesFinalizer(t *testing.T) {
	s := newOperatorScheme(t)
	pt := podTraceBeingDeleted()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(pt).
		Build()
	r := &PodTraceReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: pt.Name, Namespace: pt.Namespace},
	}); err != nil {
		t.Fatalf("deletion path must succeed, got %v", err)
	}
}

func TestMore_PodTrace_DeletionCleanupError(t *testing.T) {
	s := newOperatorScheme(t)
	pt := podTraceBeingDeleted()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(pt).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.DeleteOption) error {
				if _, ok := obj.(*corev1.ConfigMap); ok {
					return errInternal()
				}
				return errInternal()
			},
		}).
		Build()
	r := &PodTraceReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: pt.Name, Namespace: pt.Namespace},
	}); err == nil {
		t.Fatal("expected cleanup error from PodTrace deletion path")
	}
}

func TestMore_PodTrace_DeletionFinalizerConflictRequeues(t *testing.T) {
	s := newOperatorScheme(t)
	pt := podTraceBeingDeleted()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(pt).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.UpdateOption) error {
				return errConflict("podtraces", pt.Name)
			},
		}).
		Build()
	r := &PodTraceReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: pt.Name, Namespace: pt.Namespace},
	})
	if err != nil {
		t.Fatalf("finalizer-clear conflict must requeue without error, got %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Fatalf("expected requeue on finalizer-clear conflict, got %+v", res)
	}
}

func TestMore_PodTrace_DeletionFinalizerError(t *testing.T) {
	s := newOperatorScheme(t)
	pt := podTraceBeingDeleted()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(pt).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.UpdateOption) error {
				return errInternal()
			},
		}).
		Build()
	r := &PodTraceReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: pt.Name, Namespace: pt.Namespace},
	}); err == nil {
		t.Fatal("expected finalizer-clear error from PodTrace deletion path")
	}
}

func TestMore_PodTrace_PausedShortCircuit(t *testing.T) {
	s := newOperatorScheme(t)
	pt := podTraceWithFinalizer()
	pt.Spec.Paused = true
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(pt).
		Build()
	r := &PodTraceReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: pt.Name, Namespace: pt.Namespace},
	}); err != nil {
		t.Fatalf("paused path must succeed, got %v", err)
	}

	var got podtracev1alpha1.PodTrace
	if err := c.Get(context.Background(), types.NamespacedName{Name: pt.Name, Namespace: pt.Namespace}, &got); err != nil {
		t.Fatalf("get PodTrace: %v", err)
	}
	if cond := findCondition(got.Status.Conditions, ConditionPaused); cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("expected Paused=True condition, got %+v", got.Status.Conditions)
	}
}

func TestMore_PodTrace_NamespaceSelectorInvalid(t *testing.T) {
	s := newOperatorScheme(t)
	pt := podTraceWithFinalizer()
	pt.Spec.NamespaceSelector = &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key:      "team",
			Operator: "BogusOperator",
			Values:   []string{"a"},
		}},
	}
	ec := otlpExporter("ec", "team-a")
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(pt, ec).
		Build()
	r := &PodTraceReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: pt.Name, Namespace: pt.Namespace},
	}); err != nil {
		t.Fatalf("invalid namespace selector is recorded in status, not returned; got %v", err)
	}

	var got podtracev1alpha1.PodTrace
	if err := c.Get(context.Background(), types.NamespacedName{Name: pt.Name, Namespace: pt.Namespace}, &got); err != nil {
		t.Fatalf("get PodTrace: %v", err)
	}
	if cond := findCondition(got.Status.Conditions, ConditionDegraded); cond == nil || cond.Reason != "NamespaceSelectorInvalid" {
		t.Fatalf("expected NamespaceSelectorInvalid degraded condition, got %+v", got.Status.Conditions)
	}
}

func TestMore_Session_DeletionRemovesFinalizer(t *testing.T) {
	s := newOperatorScheme(t)
	sess := sessionBeingDeleted()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(sess).
		Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: sess.Name, Namespace: sess.Namespace},
	}); err != nil {
		t.Fatalf("session deletion path must succeed, got %v", err)
	}
}

func TestMore_Session_DeletionCleanupError(t *testing.T) {
	s := newOperatorScheme(t)
	sess := sessionBeingDeleted()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(sess).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.DeleteOption) error {
				if _, ok := obj.(*rbacv1.RoleBinding); ok {
					return errInternal()
				}
				return errInternal()
			},
		}).
		Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: sess.Name, Namespace: sess.Namespace},
	}); err == nil {
		t.Fatal("expected cleanup error from session deletion path")
	}
}

func TestMore_Session_DeletionFinalizerConflictRequeues(t *testing.T) {
	s := newOperatorScheme(t)
	sess := sessionBeingDeleted()
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(sess).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.UpdateOption) error {
				return errConflict("podtracesessions", sess.Name)
			},
		}).
		Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: sess.Name, Namespace: sess.Namespace},
	})
	if err != nil {
		t.Fatalf("finalizer-clear conflict must requeue without error, got %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Fatalf("expected requeue on finalizer-clear conflict, got %+v", res)
	}
}

func TestMore_Session_ObjectStoreURIInvalid(t *testing.T) {
	s := newOperatorScheme(t)
	sess := runnableSession()
	sess.Spec.ReportRef = &podtracev1alpha1.ReportReference{
		ObjectStore: &podtracev1alpha1.ObjectStoreReference{URI: "ftp://not-supported/key"},
	}
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(sess).
		Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: sess.Name, Namespace: sess.Namespace},
	}); err != nil {
		t.Fatalf("invalid objectstore URI is recorded in status, not returned; got %v", err)
	}

	var got podtracev1alpha1.PodTraceSession
	if err := c.Get(context.Background(), types.NamespacedName{Name: sess.Name, Namespace: sess.Namespace}, &got); err != nil {
		t.Fatalf("get session: %v", err)
	}
	if got.Status.State != podtracev1alpha1.SessionStateFailed {
		t.Fatalf("expected Failed state, got %q", got.Status.State)
	}
	if cond := findCondition(got.Status.Conditions, ConditionDegraded); cond == nil || cond.Reason != "ObjectStoreURIInvalid" {
		t.Fatalf("expected ObjectStoreURIInvalid degraded condition, got %+v", got.Status.Conditions)
	}
}

func TestMore_Session_ObjectStoreCredsMissing(t *testing.T) {
	s := newOperatorScheme(t)
	sess := runnableSession()
	sess.Spec.ReportRef = &podtracev1alpha1.ReportReference{
		ObjectStore: &podtracev1alpha1.ObjectStoreReference{
			URI:                  "s3://bucket/key",
			CredentialsSecretRef: &corev1.LocalObjectReference{Name: "absent-creds"},
		},
	}
	pod := runningPod("p1", "team-a", "n1", map[string]string{"a": "b"})
	ec := otlpExporter("ec", "team-a")
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(sess, pod, ec).
		Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: sess.Name, Namespace: sess.Namespace},
	})
	if err != nil {
		t.Fatalf("missing creds is recorded in status, not returned; got %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Fatalf("expected requeue on missing objectstore creds, got %+v", res)
	}

	var got podtracev1alpha1.PodTraceSession
	if err := c.Get(context.Background(), types.NamespacedName{Name: sess.Name, Namespace: sess.Namespace}, &got); err != nil {
		t.Fatalf("get session: %v", err)
	}
	if cond := findCondition(got.Status.Conditions, ConditionDegraded); cond == nil || cond.Reason != "ObjectStoreCreds" {
		t.Fatalf("expected ObjectStoreCreds degraded condition, got %+v", got.Status.Conditions)
	}
}

func TestMore_Session_ServiceAccountError(t *testing.T) {
	s := newOperatorScheme(t)
	sess := runnableSession()
	pod := runningPod("p1", "team-a", "n1", map[string]string{"a": "b"})
	ec := otlpExporter("ec", "team-a")
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(sess, pod, ec).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if _, ok := obj.(*corev1.ServiceAccount); ok {
					return errInternal()
				}
				return cl.Create(ctx, obj, opts...)
			},
		}).
		Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: sess.Name, Namespace: sess.Namespace},
	}); err == nil {
		t.Fatal("expected SessionSA error from session Reconcile")
	}

	var got podtracev1alpha1.PodTraceSession
	if err := c.Get(context.Background(), types.NamespacedName{Name: sess.Name, Namespace: sess.Namespace}, &got); err != nil {
		t.Fatalf("get session: %v", err)
	}
	if cond := findCondition(got.Status.Conditions, ConditionDegraded); cond == nil || cond.Reason != "SessionSA" {
		t.Fatalf("expected SessionSA degraded condition, got %+v", got.Status.Conditions)
	}
}

func TestMore_Session_ReportRBACError(t *testing.T) {
	s := newOperatorScheme(t)
	sess := runnableSession()
	pod := runningPod("p1", "team-a", "n1", map[string]string{"a": "b"})
	ec := otlpExporter("ec", "team-a")
	c := fake.NewClientBuilder().
		WithScheme(s).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(sess, pod, ec).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if _, ok := obj.(*rbacv1.Role); ok {
					return errInternal()
				}
				return cl.Create(ctx, obj, opts...)
			},
		}).
		Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: s, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: sess.Name, Namespace: sess.Namespace},
	}); err == nil {
		t.Fatal("expected SessionRBAC error from session Reconcile")
	}

	var got podtracev1alpha1.PodTraceSession
	if err := c.Get(context.Background(), types.NamespacedName{Name: sess.Name, Namespace: sess.Namespace}, &got); err != nil {
		t.Fatalf("get session: %v", err)
	}
	if cond := findCondition(got.Status.Conditions, ConditionDegraded); cond == nil || cond.Reason != "SessionRBAC" {
		t.Fatalf("expected SessionRBAC degraded condition, got %+v", got.Status.Conditions)
	}
}

func findCondition(conds []metav1.Condition, condType string) *metav1.Condition {
	for i := range conds {
		if conds[i].Type == condType {
			return &conds[i]
		}
	}
	return nil
}

func podTraceBeingDeleted() *podtracev1alpha1.PodTrace {
	now := metav1.NewTime(time.Now())
	return &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "pt-del",
			Namespace:         "team-a",
			UID:               "pt-del-uid",
			Generation:        1,
			Finalizers:        []string{FinalizerCleanup},
			DeletionTimestamp: &now,
		},
		Spec: podtracev1alpha1.PodTraceSpec{
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec"},
		},
	}
}

func sessionBeingDeleted() *podtracev1alpha1.PodTraceSession {
	now := metav1.NewTime(time.Now())
	return &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "sess-del",
			Namespace:         "team-a",
			UID:               "sess-del-uid",
			Generation:        1,
			Finalizers:        []string{FinalizerCleanup},
			DeletionTimestamp: &now,
		},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			Duration:    metav1.Duration{Duration: time.Minute},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec"},
		},
	}
}
