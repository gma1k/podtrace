package operator

import (
	"context"
	"reflect"
	"strings"
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

func TestMergeSortedNamespaceSets(t *testing.T) {
	cases := []struct {
		name string
		a, b []string
		want []string
	}{
		{"a-empty", nil, []string{"x", "y"}, []string{"x", "y"}},
		{"b-empty", []string{"x"}, nil, []string{"x"}},
		{"union-dedup-sort", []string{"b", "a"}, []string{"c", "a"}, []string{"a", "b", "c"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mergeSortedNamespaceSets(tc.a, tc.b)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("mergeSortedNamespaceSets(%v,%v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestResolveTracerConfig_PresentAbsentError(t *testing.T) {
	scheme := newOperatorScheme(t)

	t.Run("present", func(t *testing.T) {
		tc := &podtracev1alpha1.TracerConfig{
			ObjectMeta: metav1.ObjectMeta{Name: DefaultTracerConfigName},
			Spec:       podtracev1alpha1.TracerConfigSpec{SystemNamespace: "custom-ns"},
		}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tc).Build()
		r := &PodTraceSessionReconciler{Client: c, Scheme: scheme}
		got, err := r.resolveTracerConfig(context.Background())
		if err != nil || got == nil {
			t.Fatalf("resolveTracerConfig present: got=%v err=%v", got, err)
		}
		if got.Spec.SystemNamespace != "custom-ns" {
			t.Errorf("wrong TracerConfig returned: %+v", got.Spec)
		}
	})

	t.Run("absent", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		r := &PodTraceSessionReconciler{Client: c, Scheme: scheme}
		got, err := r.resolveTracerConfig(context.Background())
		if err != nil {
			t.Fatalf("absent TracerConfig must not error, got %v", err)
		}
		if got != nil {
			t.Errorf("absent TracerConfig must return nil, got %+v", got)
		}
	})

	t.Run("error", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).
			WithInterceptorFuncs(interceptor.Funcs{
				Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
					if _, ok := obj.(*podtracev1alpha1.TracerConfig); ok {
						return errInternal()
					}
					return nil
				},
			}).Build()
		r := &PodTraceSessionReconciler{Client: c, Scheme: scheme}
		if _, err := r.resolveTracerConfig(context.Background()); err == nil {
			t.Fatal("expected error from TracerConfig Get failure")
		}
	})
}

func TestResolveSessionTargets_InvalidNamespaceSelector(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme}
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "team-a"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			NamespaceSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "k", Operator: "BOGUS"}},
			},
		},
	}
	if _, err := r.resolveSessionTargets(context.Background(), s); err == nil ||
		!strings.Contains(err.Error(), "invalid NamespaceSelector") {
		t.Fatalf("expected invalid NamespaceSelector error, got %v", err)
	}
}

func TestResolveSessionTargets_InvalidSelector(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme}
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "team-a"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "k", Operator: "BOGUS"}},
			},
		},
	}
	if _, err := r.resolveSessionTargets(context.Background(), s); err == nil ||
		!strings.Contains(err.Error(), "invalid selector") {
		t.Fatalf("expected invalid selector error, got %v", err)
	}
}

func TestResolveSessionTargets_SelectorNilClearsNamespaces(t *testing.T) {
	scheme := newOperatorScheme(t)
	granted := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:        "team-b",
		Labels:      map[string]string{"tier": "app"},
		Annotations: map[string]string{podtracev1alpha1.AllowTracingFromAnnotation: "team-a"},
	}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(granted).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme}
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "team-a"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "app"}},
		},
	}
	out, err := r.resolveSessionTargets(context.Background(), s)
	if err != nil {
		t.Fatalf("resolveSessionTargets: %v", err)
	}
	if len(out.Namespaces) != 0 {
		t.Errorf("namespaces should be cleared when Selector is nil, got %v", out.Namespaces)
	}
	if len(out.Nodes) != 0 {
		t.Errorf("no pods can match without a Selector, got nodes %v", out.Nodes)
	}
}

func TestResolveSessionTargets_PodRefsRunningAndMissing(t *testing.T) {
	scheme := newOperatorScheme(t)
	running := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app-0", Namespace: "team-a"},
		Spec:       corev1.PodSpec{NodeName: "node-1"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(running).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme}
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "team-a"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			PodRefs: []podtracev1alpha1.PodRef{{Name: "app-0"}, {Name: "gone"}},
		},
	}
	out, err := r.resolveSessionTargets(context.Background(), s)
	if err != nil {
		t.Fatalf("resolveSessionTargets: %v", err)
	}
	if len(out.Nodes) != 1 || out.Nodes[0] != "node-1" {
		t.Errorf("nodes = %v, want [node-1]", out.Nodes)
	}
}

func TestResolveSessionTargets_PodRefGetError(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.Pod); ok {
					return errInternal()
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		}).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme}
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "team-a"},
		Spec:       podtracev1alpha1.PodTraceSessionSpec{PodRefs: []podtracev1alpha1.PodRef{{Name: "app-0"}}},
	}
	if _, err := r.resolveSessionTargets(context.Background(), s); err == nil {
		t.Fatal("expected pod Get error to propagate")
	}
}

func TestResolveSessionTargets_FilterGrantedPodRefsError(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.Namespace); ok {
					return errInternal()
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		}).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme}
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "team-a"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			PodRefs: []podtracev1alpha1.PodRef{{Namespace: "team-b", Name: "app-0"}},
		},
	}
	if _, err := r.resolveSessionTargets(context.Background(), s); err == nil {
		t.Fatal("expected cross-namespace grant-check error")
	}
}

func TestResolveSessionTargets_AllowlistPodListError(t *testing.T) {
	scheme := newOperatorScheme(t)
	granted := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:        "team-b",
		Labels:      map[string]string{"tier": "app"},
		Annotations: map[string]string{podtracev1alpha1.AllowTracingFromAnnotation: "team-a"},
	}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(granted).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*corev1.PodList); ok {
					return errInternal()
				}
				return cl.List(ctx, list, opts...)
			},
		}).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme}
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "team-a"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "app"}},
			Selector:          &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
		},
	}
	if _, err := r.resolveSessionTargets(context.Background(), s); err == nil {
		t.Fatal("expected pod List error in allowlist branch")
	}
}

func TestReconcileTerminalSession_DeleteError(t *testing.T) {
	scheme := newOperatorScheme(t)
	past := metav1.NewTime(time.Now().Add(-time.Hour))
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "team-a"},
		Status: podtracev1alpha1.PodTraceSessionStatus{
			State:          podtracev1alpha1.SessionStateCompleted,
			CompletionTime: &past,
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.DeleteOption) error {
				if _, ok := obj.(*podtracev1alpha1.PodTraceSession); ok {
					return errInternal()
				}
				return nil
			},
		}).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme}
	if _, err := r.reconcileTerminalSession(context.Background(), s); err == nil {
		t.Fatal("expected delete error for expired session")
	}
}

func TestReconcileTerminalSession_WithinTTLRequeues(t *testing.T) {
	scheme := newOperatorScheme(t)
	now := metav1.Now()
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "team-a"},
		Status: podtracev1alpha1.PodTraceSessionStatus{
			State:          podtracev1alpha1.SessionStateFailed,
			CompletionTime: &now,
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme}
	res, err := r.reconcileTerminalSession(context.Background(), s)
	if err != nil {
		t.Fatalf("reconcileTerminalSession: %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Errorf("expected a positive requeue while within TTL, got %v", res.RequeueAfter)
	}

	if err := c.Get(context.Background(), types.NamespacedName{Name: "s", Namespace: "team-a"}, &podtracev1alpha1.PodTraceSession{}); err != nil {
		t.Errorf("session must not be deleted within TTL: %v", err)
	}
}
