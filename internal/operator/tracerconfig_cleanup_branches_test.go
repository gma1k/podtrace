package operator

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func newTracerConfigCleanupReconciler(t *testing.T, stale client.Object) *TracerConfigReconciler {
	t.Helper()
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(stale).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.DeleteOption) error {
				return errInternal()
			},
		}).Build()
	return &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}
}

func TestTCCleanupBranch_DaemonSetDeleteError(t *testing.T) {
	labels := map[string]string{LabelManagedBy: ManagedByValue, LabelComponent: ComponentAgent}
	r := newTracerConfigCleanupReconciler(t, &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: AgentDaemonSetName(), Namespace: "old-ns", Labels: labels},
	})
	if err := r.cleanupStaleAgentNamespaces(context.Background(), "podtrace-system"); err == nil {
		t.Fatal("stale DaemonSet delete failure must be surfaced")
	}
}

func TestTCCleanupBranch_ServiceAccountDeleteError(t *testing.T) {
	labels := map[string]string{LabelManagedBy: ManagedByValue, LabelComponent: ComponentAgent}
	r := newTracerConfigCleanupReconciler(t, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: AgentServiceAccountName(), Namespace: "old-ns", Labels: labels},
	})
	if err := r.cleanupStaleAgentNamespaces(context.Background(), "podtrace-system"); err == nil {
		t.Fatal("stale ServiceAccount delete failure must be surfaced")
	}
}

func TestTCCleanupBranch_RoleDeleteError(t *testing.T) {
	labels := map[string]string{LabelManagedBy: ManagedByValue, LabelComponent: ComponentAgent}
	r := newTracerConfigCleanupReconciler(t, &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: AgentBundleRoleName(), Namespace: "old-ns", Labels: labels},
	})
	if err := r.cleanupStaleAgentNamespaces(context.Background(), "podtrace-system"); err == nil {
		t.Fatal("stale Role delete failure must be surfaced")
	}
}

func TestTCCleanupBranch_RoleBindingDeleteError(t *testing.T) {
	labels := map[string]string{LabelManagedBy: ManagedByValue, LabelComponent: ComponentAgent}
	r := newTracerConfigCleanupReconciler(t, &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: AgentBundleRoleBindingName(), Namespace: "old-ns", Labels: labels},
	})
	if err := r.cleanupStaleAgentNamespaces(context.Background(), "podtrace-system"); err == nil {
		t.Fatal("stale RoleBinding delete failure must be surfaced")
	}
}

func TestTCReconcileBranch_RBACErrorStatusUpdateAlsoFails(t *testing.T) {
	scheme := newOperatorScheme(t)
	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: DefaultTracerConfigName, Generation: 1},
		Spec:       podtracev1alpha1.TracerConfigSpec{Image: "ghcr.io/gma1k/podtrace:test"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.TracerConfig{}).
		WithObjects(tc).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if _, ok := obj.(*corev1.ServiceAccount); ok {
					return errInternal()
				}
				return cl.Create(ctx, obj, opts...)
			},
			SubResourceUpdate: func(_ context.Context, _ client.Client, _ string, _ client.Object, _ ...client.SubResourceUpdateOption) error {
				return errInternal()
			},
		}).Build()
	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: DefaultTracerConfigName},
	}); err == nil {
		t.Fatal("RBAC failure must surface as a Reconcile error even when the status write also fails")
	}
}

func TestTCReconcileBranch_DaemonSetErrorStatusUpdateAlsoFails(t *testing.T) {
	scheme := newOperatorScheme(t)
	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: DefaultTracerConfigName, Generation: 1},
		Spec:       podtracev1alpha1.TracerConfigSpec{Image: "ghcr.io/gma1k/podtrace:test"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.TracerConfig{}).
		WithObjects(tc).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if _, ok := obj.(*appsv1.DaemonSet); ok {
					return errInternal()
				}
				return cl.Create(ctx, obj, opts...)
			},
			SubResourceUpdate: func(_ context.Context, _ client.Client, _ string, _ client.Object, _ ...client.SubResourceUpdateOption) error {
				return errInternal()
			},
		}).Build()
	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: DefaultTracerConfigName},
	}); err == nil {
		t.Fatal("DaemonSet failure must surface as a Reconcile error even when the status write also fails")
	}
}
