package operator

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func TestSessionBranch_DeletionTracerConfigUnreadable(t *testing.T) {
	scheme := newOperatorScheme(t)
	now := metav1.Now()
	s := sessMoreSession(func(s *podtracev1alpha1.PodTraceSession) { s.DeletionTimestamp = &now })
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(s).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*podtracev1alpha1.TracerConfig); ok {
					return errInternal()
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		}).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sessMoreSysNS}

	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("deletion must fall back to default system namespace when TracerConfig is unreadable, got %v", err)
	}
	var got podtracev1alpha1.PodTraceSession
	err := c.Get(context.Background(), types.NamespacedName{Name: "s", Namespace: "default"}, &got)
	if err == nil && len(got.Finalizers) != 0 {
		t.Fatalf("finalizer should be cleared after cleanup, got %v", got.Finalizers)
	}
}

func TestSessionBranch_SetFinalizerConflictRequeues(t *testing.T) {
	scheme := newOperatorScheme(t)
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "default", UID: "uid-s", Generation: 1},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			Duration:    metav1.Duration{Duration: time.Minute},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec"},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(s).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.UpdateOption) error {
				if _, ok := obj.(*podtracev1alpha1.PodTraceSession); ok {
					return errConflict("podtracesessions", "s")
				}
				return nil
			},
		}).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sessMoreSysNS}

	res, err := sessMoreReconcile(t, r)
	if err != nil {
		t.Fatalf("a conflict while adding the finalizer must requeue without error, got %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Fatalf("expected a requeue after finalizer-set conflict, got %+v", res)
	}
}

func TestSessionBranch_SecretToSessionsListError(t *testing.T) {
	scheme := newOperatorScheme(t)
	ec := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ec", Namespace: "team-a"},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{
				Endpoint:          "otel:4318",
				Protocol:          podtracev1alpha1.OTLPProtocolHTTP,
				HeadersFromSecret: &podtracev1alpha1.LocalObjectReference{Name: "creds"},
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ec).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*podtracev1alpha1.PodTraceSessionList); ok {
					return errInternal()
				}
				return cl.List(ctx, list, opts...)
			},
		}).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sessMoreSysNS}

	got := r.secretToPodTraceSessions(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "creds", Namespace: "team-a"},
	})
	if got != nil {
		t.Fatalf("a failed session list must yield no requeue requests, got %v", got)
	}
}

func TestSessionBranch_EnsureJobsListOwnedError(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
				return errInternal()
			},
		}).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sessMoreSysNS}

	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "team-a", UID: "uid-s"},
	}
	if _, err := r.ensureJobs(context.Background(), s, nil, sessionTargets{Nodes: nil}, nil); err == nil {
		t.Fatal("ensureJobs must surface the owned-Job list error")
	}
}
