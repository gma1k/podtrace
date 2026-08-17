package operator

import (
	"context"
	"reflect"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func subjectNamespaces(subs []rbacv1.Subject) []string {
	out := make([]string, 0, len(subs))
	for _, sub := range subs {
		out = append(out, sub.Namespace)
	}
	return out
}

func TestEnsureSessionReportRBAC_SubjectPerSystemNamespace(t *testing.T) {
	scheme := newOperatorScheme(t)
	s := finTestSession()
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	ctx := context.Background()

	if err := ensureSessionReportRBAC(ctx, c, s, scheme, []string{"fleet-a", "fleet-b"}); err != nil {
		t.Fatalf("ensureSessionReportRBAC: %v", err)
	}

	var rb rbacv1.RoleBinding
	if err := c.Get(ctx, types.NamespacedName{Name: SessionReportRoleBindingName(s.UID), Namespace: s.Namespace}, &rb); err != nil {
		t.Fatalf("get report RoleBinding: %v", err)
	}
	if got, want := subjectNamespaces(rb.Subjects), []string{"fleet-a", "fleet-b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("report binding subject namespaces = %v, want %v", got, want)
	}
	for _, sub := range rb.Subjects {
		if sub.Name != SessionServiceAccountName(s.UID) {
			t.Errorf("subject name = %q, want %q", sub.Name, SessionServiceAccountName(s.UID))
		}
		if sub.Kind != rbacv1.ServiceAccountKind {
			t.Errorf("subject kind = %q, want %q", sub.Kind, rbacv1.ServiceAccountKind)
		}
	}
}

func TestEnsureSessionPodReadRBAC_SubjectPerSystemNamespace(t *testing.T) {
	scheme := newOperatorScheme(t)
	s := finTestSession()
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	ctx := context.Background()

	if err := ensureSessionPodReadRBAC(ctx, c, s, scheme, []string{"team-x"}, []string{"fleet-a", "fleet-b"}); err != nil {
		t.Fatalf("ensureSessionPodReadRBAC: %v", err)
	}

	var rb rbacv1.RoleBinding
	if err := c.Get(ctx, types.NamespacedName{Name: SessionPodReadRoleBindingName(s.UID), Namespace: "team-x"}, &rb); err != nil {
		t.Fatalf("get pod-read RoleBinding: %v", err)
	}
	if got, want := subjectNamespaces(rb.Subjects), []string{"fleet-a", "fleet-b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pod-read binding subject namespaces = %v, want %v", got, want)
	}
}

func TestSessionSubjects_DeduplicatesAndSkipsEmpty(t *testing.T) {
	s := finTestSession()
	subs := sessionSubjects(s, []string{"fleet-a", "", "fleet-a", "fleet-b"})
	if got, want := subjectNamespaces(subs), []string{"fleet-a", "fleet-b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("subject namespaces = %v, want %v", got, want)
	}
}
