package operator

import (
	"context"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func hasNamespace(list []string, ns string) bool {
	for _, n := range list {
		if n == ns {
			return true
		}
	}
	return false
}

func TestSessionChildNamespaces_UnionsSeedAndDiscovered(t *testing.T) {
	scheme := newOperatorScheme(t)
	s := finTestSession()
	staleJob := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{
		Name: "job-x", Namespace: "fleet-gone", UID: "job-x-uid", Labels: sessionRBACLabels(s),
	}}
	staleSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: SessionBundleName(s.UID), Namespace: "fleet-also-gone", Labels: sessionRBACLabels(s),
	}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(staleJob, staleSecret).Build()

	got, err := sessionChildNamespaces(context.Background(), c, s, []string{"podtrace-system"})
	if err != nil {
		t.Fatalf("sessionChildNamespaces: %v", err)
	}
	for _, want := range []string{"podtrace-system", "fleet-gone", "fleet-also-gone"} {
		if !hasNamespace(got, want) {
			t.Errorf("namespace %q missing from %v", want, got)
		}
	}
}

func TestSessionReconcile_DeletionSweepsStaleNamespaceChildren(t *testing.T) {
	scheme := newOperatorScheme(t)
	now := metav1.Now()
	s := sessMoreSession(func(s *podtracev1alpha1.PodTraceSession) { s.DeletionTimestamp = &now })
	staleJob := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{
		Name: "job-stale", Namespace: "fleet-gone", UID: "job-stale-uid",
		Labels: map[string]string{
			LabelManagedBy:   ManagedByValue,
			LabelComponent:   ComponentSession,
			LabelSessionName: s.Name,
			LabelSessionNS:   s.Namespace,
		},
	}}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(s, staleJob).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sessMoreSysNS}

	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("deletion reconcile: %v", err)
	}

	err := c.Get(context.Background(), types.NamespacedName{Name: "job-stale", Namespace: "fleet-gone"}, &batchv1.Job{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("stale-namespace Job should have been swept before the finalizer cleared, err = %v", err)
	}
}
