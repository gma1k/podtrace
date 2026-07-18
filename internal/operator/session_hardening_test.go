package operator

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func sessionWithConfigMapReport(name, namespace, uid, cmName string) *podtracev1alpha1.PodTraceSession {
	return &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, UID: types.UID(uid)},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			ReportRef: &podtracev1alpha1.ReportReference{
				ConfigMap: &corev1.LocalObjectReference{Name: cmName},
			},
		},
	}
}

func TestEnsureSessionReportObject_RefusesForeignObject(t *testing.T) {
	scheme := newRBACScheme(t)
	ctx := context.Background()

	t.Run("refuses-preexisting-user-object", func(t *testing.T) {
		userCM := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
			Name: "app-config", Namespace: "team-a",
			Labels: map[string]string{"app": "billing"},
		}, Data: map[string]string{"secret": "keepme"}}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(userCM).Build()

		s := sessionWithConfigMapReport("diag", "team-a", "u1", "app-config")
		err := ensureSessionReportObject(ctx, c, s)
		var conflict *reportObjectConflictError
		if !errors.As(err, &conflict) {
			t.Fatalf("expected reportObjectConflictError, got %v", err)
		}

		var got corev1.ConfigMap
		if err := c.Get(ctx, types.NamespacedName{Name: "app-config", Namespace: "team-a"}, &got); err != nil {
			t.Fatal(err)
		}
		if got.Data["secret"] != "keepme" {
			t.Errorf("user ConfigMap was mutated: %+v", got.Data)
		}
	})

	t.Run("refuses-other-sessions-object", func(t *testing.T) {
		other := sessionWithConfigMapReport("other", "team-a", "u-other", "shared-report")
		labels := sessionRBACLabels(other)
		labels[reportManagedBy] = reportManagedVal
		labels[labelReportKind] = reportKindValue
		otherCM := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
			Name: "shared-report", Namespace: "team-a", Labels: labels,
		}}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(otherCM).Build()

		s := sessionWithConfigMapReport("diag", "team-a", "u1", "shared-report")
		if err := ensureSessionReportObject(ctx, c, s); err == nil {
			t.Fatal("expected conflict adopting another session's report object")
		}
	})

	t.Run("creates-when-absent", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		s := sessionWithConfigMapReport("diag", "team-a", "u1", "fresh-report")
		if err := ensureSessionReportObject(ctx, c, s); err != nil {
			t.Fatalf("create fresh report object: %v", err)
		}
		var cm corev1.ConfigMap
		if err := c.Get(ctx, types.NamespacedName{Name: "fresh-report", Namespace: "team-a"}, &cm); err != nil {
			t.Fatalf("report object not created: %v", err)
		}
		if !reportObjectOwnedBySession(cm.Labels, s) {
			t.Errorf("created object missing ownership labels: %+v", cm.Labels)
		}
	})

	t.Run("adopts-own-object-idempotently", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		s := sessionWithConfigMapReport("diag", "team-a", "u1", "my-report")
		if err := ensureSessionReportObject(ctx, c, s); err != nil {
			t.Fatal(err)
		}
		if err := ensureSessionReportObject(ctx, c, s); err != nil {
			t.Fatalf("re-reconcile must adopt own object: %v", err)
		}
	})
}

func TestSessionServiceAccount_IsPerSession(t *testing.T) {
	if SessionServiceAccountName("aaaa11112222") == SessionServiceAccountName("bbbb33334444") {
		t.Fatal("two sessions must not share a ServiceAccount name")
	}
	scheme := newRBACScheme(t)
	ctx := context.Background()
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	s1 := &podtracev1alpha1.PodTraceSession{ObjectMeta: metav1.ObjectMeta{Name: "s1", Namespace: "team-a", UID: "uid-one-000"}}
	s2 := &podtracev1alpha1.PodTraceSession{ObjectMeta: metav1.ObjectMeta{Name: "s2", Namespace: "team-b", UID: "uid-two-000"}}
	for _, s := range []*podtracev1alpha1.PodTraceSession{s1, s2} {
		if err := ensureSessionServiceAccount(ctx, c, s, "podtrace-system"); err != nil {
			t.Fatalf("ensure SA %s: %v", s.Name, err)
		}
	}

	var sa1, sa2 corev1.ServiceAccount
	if err := c.Get(ctx, types.NamespacedName{Name: SessionServiceAccountName(s1.UID), Namespace: "podtrace-system"}, &sa1); err != nil {
		t.Fatalf("SA for s1 missing: %v", err)
	}
	if err := c.Get(ctx, types.NamespacedName{Name: SessionServiceAccountName(s2.UID), Namespace: "podtrace-system"}, &sa2); err != nil {
		t.Fatalf("SA for s2 missing: %v", err)
	}
	if sa1.Labels[LabelSessionName] != "s1" || sa2.Labels[LabelSessionName] != "s2" {
		t.Errorf("per-session SAs must carry their own session labels: %v / %v", sa1.Labels, sa2.Labels)
	}

	if err := cleanupSessionServiceAccount(ctx, c, s1, "podtrace-system"); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, types.NamespacedName{Name: SessionServiceAccountName(s1.UID), Namespace: "podtrace-system"}, &sa1); !apierrors.IsNotFound(err) {
		t.Errorf("s1 SA should be deleted, got %v", err)
	}
	if err := c.Get(ctx, types.NamespacedName{Name: SessionServiceAccountName(s2.UID), Namespace: "podtrace-system"}, &sa2); err != nil {
		t.Errorf("s2 SA must survive s1 cleanup: %v", err)
	}
}
