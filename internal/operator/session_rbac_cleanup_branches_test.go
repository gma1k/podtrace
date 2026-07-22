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

func rbacTestSession() *podtracev1alpha1.PodTraceSession {
	return &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "team-a", UID: "sess-uid"},
	}
}

func TestCleanupPodReadRBAC_RoleBindingDeleteError(t *testing.T) {
	scheme := newOperatorScheme(t)
	s := rbacTestSession()
	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SessionPodReadRoleBindingName(s.UID),
			Namespace: "granted-ns",
			Labels:    sessionRBACLabels(s),
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(binding).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.DeleteOption) error {
				if _, ok := obj.(*rbacv1.RoleBinding); ok {
					return errInternal()
				}
				return nil
			},
		}).Build()

	if err := cleanupSessionPodReadRBAC(context.Background(), c, s); err == nil {
		t.Fatal("pod-read RoleBinding delete failure must be surfaced")
	}
}

func TestCleanupPodReadRBAC_RoleDeleteError(t *testing.T) {
	scheme := newOperatorScheme(t)
	s := rbacTestSession()
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SessionPodReadRoleName(s.UID),
			Namespace: "granted-ns",
			Labels:    sessionRBACLabels(s),
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(role).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.DeleteOption) error {
				if _, ok := obj.(*rbacv1.Role); ok {
					return errInternal()
				}
				return nil
			},
		}).Build()

	if err := cleanupSessionPodReadRBAC(context.Background(), c, s); err == nil {
		t.Fatal("pod-read Role delete failure must be surfaced")
	}
}

func TestEnsureSessionReportObject_InspectExistingError(t *testing.T) {
	scheme := newOperatorScheme(t)
	s := rbacTestSession()
	s.Spec.ReportRef = &podtracev1alpha1.ReportReference{
		ConfigMap: &corev1.LocalObjectReference{Name: "report-cm"},
	}
	existing := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "report-cm", Namespace: s.Namespace},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
				if _, ok := obj.(*corev1.ConfigMap); ok {
					return errInternal()
				}
				return nil
			},
		}).Build()

	if err := ensureSessionReportObject(context.Background(), c, s); err == nil {
		t.Fatal("failure to inspect the pre-existing report object must be surfaced")
	}
}
