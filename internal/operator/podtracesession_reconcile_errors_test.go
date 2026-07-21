package operator

import (
	"context"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

const sessMoreSysNS = "ns-sys"

func sessMoreFanOutObjects() []client.Object {
	return []client.Object{
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "default", Labels: map[string]string{"a": "b"}},
			Spec:       corev1.PodSpec{NodeName: "n1"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
		&podtracev1alpha1.ExporterConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "ec", Namespace: "default"},
			Spec: podtracev1alpha1.ExporterConfigSpec{
				Type: podtracev1alpha1.ExporterTypeOTLP,
				OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "otel:4318", Protocol: podtracev1alpha1.OTLPProtocolHTTP},
			},
		},
	}
}

func sessMoreSession(mutate func(*podtracev1alpha1.PodTraceSession)) *podtracev1alpha1.PodTraceSession {
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{
			Name: "s", Namespace: "default", UID: "uid-s", Generation: 3,
			Finalizers: []string{FinalizerCleanup},
		},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			Duration:    metav1.Duration{Duration: time.Minute},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec"},
		},
	}
	if mutate != nil {
		mutate(s)
	}
	return s
}

func sessMoreReconcile(t *testing.T, r *PodTraceSessionReconciler) (ctrl.Result, error) {
	t.Helper()
	return r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "s", Namespace: "default"},
	})
}

func TestSessionReconcile_GetError(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
				if _, ok := obj.(*podtracev1alpha1.PodTraceSession); ok {
					return errInternal()
				}
				return nil
			},
		}).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sessMoreSysNS}
	if _, err := sessMoreReconcile(t, r); err == nil {
		t.Fatal("expected non-NotFound Get error to propagate")
	}
}

func TestSessionReconcile_SetFinalizerError(t *testing.T) {
	scheme := newOperatorScheme(t)
	s := sessMoreSession(func(s *podtracev1alpha1.PodTraceSession) { s.Finalizers = nil })
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.UpdateOption) error {
				if _, ok := obj.(*podtracev1alpha1.PodTraceSession); ok {
					return errInternal()
				}
				return nil
			},
		}).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sessMoreSysNS}
	if _, err := sessMoreReconcile(t, r); err == nil {
		t.Fatal("expected set-finalizer update error")
	}
}

func TestSessionReconcile_DeletionClearFinalizerError(t *testing.T) {
	scheme := newOperatorScheme(t)
	now := metav1.Now()
	s := sessMoreSession(func(s *podtracev1alpha1.PodTraceSession) { s.DeletionTimestamp = &now })
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.UpdateOption) error {
				if _, ok := obj.(*podtracev1alpha1.PodTraceSession); ok {
					return errInternal()
				}
				return nil
			},
		}).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sessMoreSysNS}
	if _, err := sessMoreReconcile(t, r); err == nil {
		t.Fatal("expected clear-finalizer update error during deletion")
	}
}

func TestSessionReconcile_NamespaceSelectorInvalidFailsTerminally(t *testing.T) {
	scheme := newOperatorScheme(t)
	s := sessMoreSession(func(s *podtracev1alpha1.PodTraceSession) {
		s.Spec.NamespaceSelector = &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "k", Operator: "BOGUS"}},
		}
	})
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(s).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sessMoreSysNS}
	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("terminal failure must not return error: %v", err)
	}
	var got podtracev1alpha1.PodTraceSession
	if err := c.Get(context.Background(), types.NamespacedName{Name: "s", Namespace: "default"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.State != podtracev1alpha1.SessionStateFailed {
		t.Errorf("state = %q, want Failed", got.Status.State)
	}
}

func TestSessionReconcile_NoMatchedPodsCrossNamespaceDenied(t *testing.T) {
	scheme := newOperatorScheme(t)
	ungranted := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:   "ungranted",
		Labels: map[string]string{"team": "obs"},
	}}
	podInUngranted := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ungranted", Labels: map[string]string{"a": "b"}},
		Spec:       corev1.PodSpec{NodeName: "n9"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	s := sessMoreSession(func(s *podtracev1alpha1.PodTraceSession) {
		s.Spec.NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"team": "obs"}}
	})
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(s, ungranted, podInUngranted).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sessMoreSysNS}
	res, err := sessMoreReconcile(t, r)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Error("expected requeue while waiting for grant")
	}
	var got podtracev1alpha1.PodTraceSession
	if err := c.Get(context.Background(), types.NamespacedName{Name: "s", Namespace: "default"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.State != podtracev1alpha1.SessionStatePending {
		t.Errorf("state = %q, want Pending", got.Status.State)
	}
	if !hasCondition(got.Status.Conditions, ConditionReconciled, metav1.ConditionTrue) {
		t.Errorf("expected Reconciled condition, got %+v", got.Status.Conditions)
	}
}

func TestSessionReconcile_ResolveTracerConfigError(t *testing.T) {
	scheme := newOperatorScheme(t)
	s := sessMoreSession(nil)
	objs := append(sessMoreFanOutObjects(), s)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(objs...).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*podtracev1alpha1.TracerConfig); ok {
					return errInternal()
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		}).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sessMoreSysNS}
	if _, err := sessMoreReconcile(t, r); err == nil {
		t.Fatal("expected TracerConfig resolve error to propagate")
	}
}

func TestSessionReconcile_ReportObjectConflictFailsTerminally(t *testing.T) {
	scheme := newOperatorScheme(t)
	foreign := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Name: "shared-report", Namespace: "default", Labels: map[string]string{"owner": "someone-else"},
	}}
	s := sessMoreSession(func(s *podtracev1alpha1.PodTraceSession) {
		s.Spec.ReportRef = &podtracev1alpha1.ReportReference{ConfigMap: &corev1.LocalObjectReference{Name: "shared-report"}}
	})
	objs := append(sessMoreFanOutObjects(), s, foreign)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(objs...).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sessMoreSysNS}
	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("report-conflict terminal failure must not return error: %v", err)
	}
	var got podtracev1alpha1.PodTraceSession
	if err := c.Get(context.Background(), types.NamespacedName{Name: "s", Namespace: "default"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.State != podtracev1alpha1.SessionStateFailed {
		t.Errorf("state = %q, want Failed on report object conflict", got.Status.State)
	}
}

func TestSessionReconcile_ReportObjectGenericError(t *testing.T) {
	scheme := newOperatorScheme(t)
	s := sessMoreSession(func(s *podtracev1alpha1.PodTraceSession) {
		s.Spec.ReportRef = &podtracev1alpha1.ReportReference{ConfigMap: &corev1.LocalObjectReference{Name: "my-report"}}
	})
	objs := append(sessMoreFanOutObjects(), s)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(objs...).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if cm, ok := obj.(*corev1.ConfigMap); ok && cm.Name == "my-report" {
					return errInternal()
				}
				return cl.Create(ctx, obj, opts...)
			},
		}).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sessMoreSysNS}
	if _, err := sessMoreReconcile(t, r); err == nil {
		t.Fatal("expected generic report-object error to propagate")
	}
}

func TestSessionReconcile_TerminalWhenAllJobsSucceed(t *testing.T) {
	scheme := newOperatorScheme(t)
	s := sessMoreSession(nil)
	started := metav1.NewTime(time.Now().Add(-time.Minute))
	done := metav1.Now()
	completedJob := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SessionJobName(s.UID, "n1"),
			Namespace: sessMoreSysNS,
			Labels: map[string]string{
				LabelManagedBy:   ManagedByValue,
				LabelComponent:   ComponentSession,
				LabelSessionName: s.Name,
				LabelSessionNS:   s.Namespace,
				LabelNodeName:    "n1",
			},
		},
		Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "podtrace", Image: "img"}}},
		}},
		Status: batchv1.JobStatus{Succeeded: 1, StartTime: &started, CompletionTime: &done},
	}
	objs := append(sessMoreFanOutObjects(), s, completedJob)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(objs...).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sessMoreSysNS}
	res, err := sessMoreReconcile(t, r)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Errorf("terminal session should not requeue, got %v", res.RequeueAfter)
	}
	var got podtracev1alpha1.PodTraceSession
	if err := c.Get(context.Background(), types.NamespacedName{Name: "s", Namespace: "default"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.State != podtracev1alpha1.SessionStateCompleted {
		t.Errorf("state = %q, want Completed", got.Status.State)
	}
	if got.Status.CompletionTime == nil {
		t.Error("CompletionTime must be stamped on terminal session")
	}
	if got.Status.StartTime == nil {
		t.Error("StartTime must be stamped when a Job has started")
	}
}

func TestSessionReconcile_DeniedAndGrantedMix(t *testing.T) {
	scheme := newOperatorScheme(t)
	granted := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:        "granted",
		Labels:      map[string]string{"team": "obs"},
		Annotations: map[string]string{podtracev1alpha1.AllowTracingFromAnnotation: "default"},
	}}
	deniedNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:   "denied",
		Labels: map[string]string{"team": "obs"},
	}}
	grantedPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "granted", Labels: map[string]string{"a": "b"}},
		Spec:       corev1.PodSpec{NodeName: "ng"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	deniedPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pd", Namespace: "denied", Labels: map[string]string{"a": "b"}},
		Spec:       corev1.PodSpec{NodeName: "nd"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	ec := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ec", Namespace: "default"},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "otel:4318", Protocol: podtracev1alpha1.OTLPProtocolHTTP},
		},
	}
	s := sessMoreSession(func(s *podtracev1alpha1.PodTraceSession) {
		s.Spec.NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"team": "obs"}}
	})
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(s, ec, granted, deniedNS, grantedPod, deniedPod).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sessMoreSysNS}
	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	var got podtracev1alpha1.PodTraceSession
	if err := c.Get(context.Background(), types.NamespacedName{Name: "s", Namespace: "default"}, &got); err != nil {
		t.Fatal(err)
	}
	reconciled := findCondition(got.Status.Conditions, ConditionReconciled)
	if reconciled == nil || !strings.Contains(reconciled.Message, "cross-namespace") {
		t.Errorf("expected cross-namespace notice in Reconciled message, got %+v", reconciled)
	}
}

func TestSessionReconcile_MapFuncListErrors(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
				return errInternal()
			},
		}).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme}

	if got := r.namespaceToPodTraceSessions(context.Background(), &corev1.Namespace{}); got != nil {
		t.Errorf("namespaceToPodTraceSessions on List error = %v, want nil", got)
	}
	if got := r.secretToPodTraceSessions(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "default"},
	}); got != nil {
		t.Errorf("secretToPodTraceSessions on List error = %v, want nil", got)
	}
}
