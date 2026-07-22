package operator

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func finalizerTestPodTrace() *podtracev1alpha1.PodTrace {
	return &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: "team-a", UID: "pt-uid"},
	}
}

func finalizerTestSession() *podtracev1alpha1.PodTraceSession {
	return &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "team-a", UID: "sess-uid"},
	}
}

func TestCleanupOrphanBundles_ConfigMapDeleteError(t *testing.T) {
	scheme := newOperatorScheme(t)
	pt := finalizerTestPodTrace()
	orphan := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ExporterBundleName(pt.UID),
			Namespace: "old-ns",
			Labels: map[string]string{
				LabelManagedBy:    ManagedByValue,
				LabelComponent:    ComponentBundle,
				LabelPodTraceName: pt.Name,
				LabelPodTraceNS:   pt.Namespace,
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(orphan).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.DeleteOption) error {
				if _, ok := obj.(*corev1.ConfigMap); ok {
					return errInternal()
				}
				return nil
			},
		}).Build()

	if err := cleanupOrphanBundles(context.Background(), c, pt, "podtrace-system"); err == nil {
		t.Fatal("orphan bundle ConfigMap delete failure must be surfaced")
	}
}

func TestCleanupOrphanBundles_SecretListError(t *testing.T) {
	scheme := newOperatorScheme(t)
	pt := finalizerTestPodTrace()
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*corev1.SecretList); ok {
					return errInternal()
				}
				return cl.List(ctx, list, opts...)
			},
		}).Build()

	if err := cleanupOrphanBundles(context.Background(), c, pt, "podtrace-system"); err == nil {
		t.Fatal("orphan bundle Secret list failure must be surfaced")
	}
}

func TestCleanupSessionChildren_PodReadRBACError(t *testing.T) {
	scheme := newOperatorScheme(t)
	s := finalizerTestSession()
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*rbacv1.RoleBindingList); ok {
					return errInternal()
				}
				return cl.List(ctx, list, opts...)
			},
		}).Build()

	if err := cleanupPodTraceSessionChildren(context.Background(), c, s, "podtrace-system"); err == nil {
		t.Fatal("session pod-read RBAC cleanup failure must be surfaced")
	}
}

func TestCleanupSessionChildren_ServiceAccountError(t *testing.T) {
	scheme := newOperatorScheme(t)
	s := finalizerTestSession()
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				if _, ok := obj.(*corev1.ServiceAccount); ok {
					return errInternal()
				}
				return cl.Delete(ctx, obj, opts...)
			},
		}).Build()

	if err := cleanupPodTraceSessionChildren(context.Background(), c, s, "podtrace-system"); err == nil {
		t.Fatal("session ServiceAccount cleanup failure must be surfaced")
	}
}
