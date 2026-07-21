package operator

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

const ptMoreSysNS = "pt-sys"

func ptMoreExporterConfig() *podtracev1alpha1.ExporterConfig {
	return &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ec", Namespace: "default"},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "otel:4318", Protocol: podtracev1alpha1.OTLPProtocolHTTP},
		},
	}
}

func ptMoreTrace(mutate func(*podtracev1alpha1.PodTrace)) *podtracev1alpha1.PodTrace {
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pt", Namespace: "default", UID: "uid-pt", Generation: 2,
			Finalizers: []string{FinalizerCleanup},
		},
		Spec: podtracev1alpha1.PodTraceSpec{ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec"}},
	}
	if mutate != nil {
		mutate(pt)
	}
	return pt
}

func ptMoreReconcile(t *testing.T, r *PodTraceReconciler) (ctrl.Result, error) {
	t.Helper()
	return r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "pt", Namespace: "default"},
	})
}

func TestPodTraceReconcile_DeletionCleanupOrphanError(t *testing.T) {
	scheme := newOperatorScheme(t)
	now := metav1.Now()
	pt := ptMoreTrace(func(pt *podtracev1alpha1.PodTrace) { pt.DeletionTimestamp = &now })
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pt).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, list client.ObjectList, _ ...client.ListOption) error {
				if _, ok := list.(*corev1.ConfigMapList); ok {
					return errInternal()
				}
				return nil
			},
		}).Build()
	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: ptMoreSysNS}
	if _, err := ptMoreReconcile(t, r); err == nil {
		t.Fatal("expected orphan-bundle cleanup error during deletion")
	}
}

func TestPodTraceReconcile_SetFinalizerConflictRequeues(t *testing.T) {
	scheme := newOperatorScheme(t)
	pt := ptMoreTrace(func(pt *podtracev1alpha1.PodTrace) { pt.Finalizers = nil })
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pt).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.UpdateOption) error {
				if _, ok := obj.(*podtracev1alpha1.PodTrace); ok {
					return errConflict("podtraces", "pt")
				}
				return nil
			},
		}).Build()
	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: ptMoreSysNS}
	res, err := ptMoreReconcile(t, r)
	if err != nil {
		t.Fatalf("finalizer conflict must be handled, got %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Error("expected requeue after finalizer conflict")
	}
}

func TestPodTraceReconcile_SetFinalizerError(t *testing.T) {
	scheme := newOperatorScheme(t)
	pt := ptMoreTrace(func(pt *podtracev1alpha1.PodTrace) { pt.Finalizers = nil })
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pt).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.UpdateOption) error {
				if _, ok := obj.(*podtracev1alpha1.PodTrace); ok {
					return errInternal()
				}
				return nil
			},
		}).Build()
	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: ptMoreSysNS}
	if _, err := ptMoreReconcile(t, r); err == nil {
		t.Fatal("expected set-finalizer error")
	}
}

func TestPodTraceReconcile_ExporterConfigGetError(t *testing.T) {
	scheme := newOperatorScheme(t)
	pt := ptMoreTrace(nil)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pt).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*podtracev1alpha1.ExporterConfig); ok {
					return errInternal()
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		}).Build()
	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: ptMoreSysNS}
	if _, err := ptMoreReconcile(t, r); err == nil {
		t.Fatal("expected ExporterConfig Get error to propagate")
	}
}

func TestPodTraceReconcile_OrphanBundleCleanupError(t *testing.T) {
	scheme := newOperatorScheme(t)
	pt := ptMoreTrace(nil)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(pt, ptMoreExporterConfig()).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*corev1.ConfigMapList); ok {
					return errInternal()
				}
				return cl.List(ctx, list, opts...)
			},
		}).Build()
	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: ptMoreSysNS}
	res, err := ptMoreReconcile(t, r)
	if err != nil {
		t.Fatalf("orphan cleanup error is degraded+requeue, not returned: %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Error("expected requeue after orphan-bundle cleanup failure")
	}
	var got podtracev1alpha1.PodTrace
	if err := c.Get(context.Background(), types.NamespacedName{Name: "pt", Namespace: "default"}, &got); err != nil {
		t.Fatal(err)
	}
	if !hasCondition(got.Status.Conditions, ConditionDegraded, metav1.ConditionTrue) {
		t.Errorf("expected Degraded=True, got %+v", got.Status.Conditions)
	}
}

func TestPodTraceReconcile_DegradedNodeStatus(t *testing.T) {
	scheme := newOperatorScheme(t)
	pt := ptMoreTrace(func(pt *podtracev1alpha1.PodTrace) {
		pt.Status.NodeStatus = []podtracev1alpha1.PodTraceNodeStatus{
			{Node: "n1", Ready: false, Message: "attach failed"},
		}
	})
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(pt, ptMoreExporterConfig()).Build()
	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: ptMoreSysNS}
	if _, err := ptMoreReconcile(t, r); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	var got podtracev1alpha1.PodTrace
	if err := c.Get(context.Background(), types.NamespacedName{Name: "pt", Namespace: "default"}, &got); err != nil {
		t.Fatal(err)
	}
	deg := findCondition(got.Status.Conditions, ConditionDegraded)
	if deg == nil || deg.Status != metav1.ConditionTrue {
		t.Fatalf("expected Degraded=True from tombstoned node, got %+v", deg)
	}
	if deg.Reason != "AgentNodeStatus" {
		t.Errorf("expected default reason AgentNodeStatus, got %q", deg.Reason)
	}
	if !strings.Contains(deg.Message, "n1") {
		t.Errorf("expected node name in message, got %q", deg.Message)
	}
}

func TestPodTraceReconcile_CrossNamespaceDenied(t *testing.T) {
	scheme := newOperatorScheme(t)
	ungranted := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:   "ungranted",
		Labels: map[string]string{"team": "obs"},
	}}
	pt := ptMoreTrace(func(pt *podtracev1alpha1.PodTrace) {
		pt.Spec.NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"team": "obs"}}
	})
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(pt, ptMoreExporterConfig(), ungranted).Build()
	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: ptMoreSysNS}
	if _, err := ptMoreReconcile(t, r); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	var got podtracev1alpha1.PodTrace
	if err := c.Get(context.Background(), types.NamespacedName{Name: "pt", Namespace: "default"}, &got); err != nil {
		t.Fatal(err)
	}
	deg := findCondition(got.Status.Conditions, ConditionDegraded)
	if deg == nil || deg.Reason != "CrossNamespaceNotGranted" {
		t.Fatalf("expected CrossNamespaceNotGranted, got %+v", deg)
	}
	reconciled := findCondition(got.Status.Conditions, ConditionReconciled)
	if reconciled == nil || !strings.Contains(reconciled.Message, "cross-namespace") {
		t.Errorf("expected cross-namespace notice in Reconciled message, got %+v", reconciled)
	}
}
