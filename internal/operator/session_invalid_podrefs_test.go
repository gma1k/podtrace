package operator

import (
	"context"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func reconcileSessionWithRefs(t *testing.T, refs []podtracev1alpha1.PodRef) *podtracev1alpha1.PodTraceSession {
	t.Helper()
	scheme := newOperatorScheme(t)
	s := sessMoreSession(func(s *podtracev1alpha1.PodTraceSession) {
		s.Spec.Selector = nil
		s.Spec.PodRefs = refs
	})
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTraceSession{}).
		WithObjects(append(sessMoreFanOutObjects(), s)...).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: sessMoreSysNS}
	if _, err := sessMoreReconcile(t, r); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var got podtracev1alpha1.PodTraceSession
	if err := c.Get(context.Background(), types.NamespacedName{Name: s.Name, Namespace: s.Namespace}, &got); err != nil {
		t.Fatal(err)
	}
	return &got
}

func TestASessionWithOnlyInvalidPodRefsSaysWhy(t *testing.T) {
	got := reconcileSessionWithRefs(t, []podtracev1alpha1.PodRef{{Name: "x,victim/db-0"}})
	cond := meta.FindStatusCondition(got.Status.Conditions, ConditionReconciled)
	if cond == nil || cond.Reason != "InvalidPodRefs" {
		t.Fatalf("Reconciled condition = %+v, want reason InvalidPodRefs", cond)
	}
	if !strings.Contains(cond.Message, "spec.podRefs[0]") {
		t.Fatalf("message %q does not name the bad ref", cond.Message)
	}
}

func TestASessionReportsTheInvalidPodRefsItSkipped(t *testing.T) {
	got := reconcileSessionWithRefs(t, []podtracev1alpha1.PodRef{{Name: "p1"}, {Namespace: "bad,ns", Name: "p2"}})
	cond := meta.FindStatusCondition(got.Status.Conditions, ConditionReconciled)
	if cond == nil || cond.Reason != "Reconciled" {
		t.Fatalf("Reconciled condition = %+v, want the session to run", cond)
	}
	if !strings.Contains(cond.Message, "invalid podRef(s) ignored: spec.podRefs[1]") {
		t.Fatalf("message %q does not report the skipped ref", cond.Message)
	}
}

func TestInvalidPodRefsListsOnlyRefsThatCannotNameAPod(t *testing.T) {
	got := invalidPodRefs([]podtracev1alpha1.PodRef{{Name: "ok"}, {Name: "Bad_Name"}, {Namespace: "team-a", Name: "fine"}})
	if len(got) != 1 || !strings.HasPrefix(got[0], "spec.podRefs[1]: ") {
		t.Fatalf("invalid = %q", got)
	}
}

func grantsEndpointSliceRead(rules []rbacv1.PolicyRule) bool {
	for _, r := range rules {
		if len(r.APIGroups) == 1 && r.APIGroups[0] == "discovery.k8s.io" &&
			len(r.Resources) == 1 && r.Resources[0] == "endpointslices" &&
			strings.Join(r.Verbs, ",") == "get,list,watch" {
			return true
		}
	}
	return false
}

func TestSessionRolesLetTheJobReadEndpointSlices(t *testing.T) {
	if !grantsEndpointSliceRead(buildSessionReportRules(nil)) {
		t.Fatal("the session's own-namespace role must grant endpointslices read")
	}

	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	s := sessMoreSession(nil)
	if err := ensureSessionPodReadRBAC(context.Background(), c, s, scheme, []string{"team-b"}, []string{sessMoreSysNS}); err != nil {
		t.Fatalf("ensureSessionPodReadRBAC: %v", err)
	}
	var role rbacv1.Role
	if err := c.Get(context.Background(), types.NamespacedName{Name: SessionPodReadRoleName(s.UID), Namespace: "team-b"}, &role); err != nil {
		t.Fatal(err)
	}
	if !grantsEndpointSliceRead(role.Rules) {
		t.Fatalf("cross-namespace role rules = %+v, want endpointslices read", role.Rules)
	}
}
