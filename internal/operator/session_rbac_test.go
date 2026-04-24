package operator

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func newRBACScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = podtracev1alpha1.AddToScheme(s)
	return s
}

func TestEnsureSessionServiceAccount_IsIdempotent(t *testing.T) {
	scheme := newRBACScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		if err := ensureSessionServiceAccount(ctx, c, "podtrace-system"); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	var sa corev1.ServiceAccount
	if err := c.Get(ctx, types.NamespacedName{Name: SessionServiceAccountName(), Namespace: "podtrace-system"}, &sa); err != nil {
		t.Fatalf("expected SA: %v", err)
	}
	if sa.Labels[LabelManagedBy] != ManagedByValue {
		t.Errorf("missing managed-by label: %+v", sa.Labels)
	}
}

func TestEnsureSessionReportRBAC_CreatesNarrowRole(t *testing.T) {
	scheme := newRBACScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	ctx := context.Background()

	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "diag", Namespace: "team-a", UID: "sess-abc"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			ReportRef: &podtracev1alpha1.ReportReference{
				ConfigMap: &corev1.LocalObjectReference{Name: "smoke-report"},
			},
		},
	}

	if err := ensureSessionReportRBAC(ctx, c, s, "podtrace-system"); err != nil {
		t.Fatalf("ensureSessionReportRBAC: %v", err)
	}

	var role rbacv1.Role
	if err := c.Get(ctx, types.NamespacedName{Name: SessionReportRoleName(s.UID), Namespace: "team-a"}, &role); err != nil {
		t.Fatalf("role not created: %v", err)
	}
	foundResourceNamed := false
	for _, rule := range role.Rules {
		for _, rn := range rule.ResourceNames {
			if rn == "smoke-report" {
				foundResourceNamed = true
			}
		}
	}
	if !foundResourceNamed {
		t.Errorf("role should scope to resourceNames=[smoke-report]: %+v", role.Rules)
	}
	// The sink resource (configmaps/secrets) MUST NOT grant
	// list/watch/delete — those are footguns for a session-scoped SA.
	// Pod and event reads DO need list/watch (the CLI uses informers);
	// this guard scopes the check to the report sink only.
	for _, rule := range role.Rules {
		isSinkRule := false
		for _, res := range rule.Resources {
			if res == "configmaps" || res == "secrets" {
				isSinkRule = true
			}
		}
		if !isSinkRule {
			continue
		}
		for _, v := range rule.Verbs {
			switch v {
			case "list", "watch", "delete", "*":
				t.Errorf("sink verb %q is too broad: %+v", v, rule.Verbs)
			}
		}
	}

	var binding rbacv1.RoleBinding
	if err := c.Get(ctx, types.NamespacedName{Name: SessionReportRoleBindingName(s.UID), Namespace: "team-a"}, &binding); err != nil {
		t.Fatalf("binding not created: %v", err)
	}
	if binding.RoleRef.Name != SessionReportRoleName(s.UID) {
		t.Errorf("binding.roleRef wrong: %+v", binding.RoleRef)
	}
	if len(binding.Subjects) != 1 ||
		binding.Subjects[0].Name != SessionServiceAccountName() ||
		binding.Subjects[0].Namespace != "podtrace-system" {
		t.Errorf("binding subject wrong: %+v", binding.Subjects)
	}
}

func TestEnsureSessionReportRBAC_NoSinkStillGrantsPodRead(t *testing.T) {
	// Sessions without a reportRef still need pod reads in the user
	// namespace so the CLI can resolve spec.podRefs / spec.selector.
	// A Role must be created for every session, even without reportRef.
	scheme := newRBACScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	ctx := context.Background()

	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "diag", Namespace: "team-a", UID: "sess-abc"},
	}
	if err := ensureSessionReportRBAC(ctx, c, s, "podtrace-system"); err != nil {
		t.Fatalf("ensureSessionReportRBAC: %v", err)
	}

	var role rbacv1.Role
	if err := c.Get(ctx, types.NamespacedName{Name: SessionReportRoleName(s.UID), Namespace: "team-a"}, &role); err != nil {
		t.Fatalf("role should exist even without reportRef: %v", err)
	}
	if !hasRuleFor(role.Rules, "pods", "get") || !hasRuleFor(role.Rules, "pods", "list") {
		t.Errorf("role missing pod read rules: %+v", role.Rules)
	}
}

func TestBuildSessionReportRules_IncludesPodReads(t *testing.T) {
	rules := buildSessionReportRules(nil)
	if !hasRuleFor(rules, "pods", "get") {
		t.Errorf("missing pods:get: %+v", rules)
	}
	if !hasRuleFor(rules, "pods", "list") {
		t.Errorf("missing pods:list: %+v", rules)
	}
	if hasRuleFor(rules, "events", "get") {
		t.Errorf("session Role must not grant events:get (operator cannot escalate): %+v", rules)
	}
	// Without reportRef, the rule set must not grant any configmap/
	// secret verbs — those need a resourceNames-scoped rule that only
	// appears when reportRef is configured.
	if hasRuleFor(rules, "configmaps", "update") || hasRuleFor(rules, "secrets", "update") {
		t.Errorf("no-reportRef ruleset leaked write verbs: %+v", rules)
	}
}

func TestBuildSessionReportRules_ResourceNamesScoped(t *testing.T) {
	rules := buildSessionReportRules(&podtracev1alpha1.ReportReference{
		ConfigMap: &corev1.LocalObjectReference{Name: "rpt"},
	})
	var scoped []rbacv1.PolicyRule
	for _, r := range rules {
		for _, res := range r.Resources {
			if res == "configmaps" && len(r.ResourceNames) > 0 {
				scoped = append(scoped, r)
			}
		}
	}
	if len(scoped) == 0 {
		t.Fatalf("no resourceNames-scoped configmap rule: %+v", rules)
	}
	if scoped[0].ResourceNames[0] != "rpt" {
		t.Errorf("resourceNames=%v want [rpt]", scoped[0].ResourceNames)
	}
	// The scoped rule must not contain the "create" verb — create is
	// checked at the collection level, so it belongs on a separate
	// unscoped rule. A scoped rule with create would be dead code.
	for _, v := range scoped[0].Verbs {
		if v == "create" {
			t.Errorf("resourceNames-scoped rule contains create verb: %+v", scoped[0])
		}
	}
}

// hasRuleFor reports whether any policy rule grants the given verb on
// the given core-API resource. Matches regardless of ResourceNames
// scoping; tests that care about that scope check ResourceNames
// directly.
func hasRuleFor(rules []rbacv1.PolicyRule, resource, verb string) bool {
	for _, r := range rules {
		resMatch := false
		for _, res := range r.Resources {
			if res == resource {
				resMatch = true
			}
		}
		if !resMatch {
			continue
		}
		for _, v := range r.Verbs {
			if v == verb {
				return true
			}
		}
	}
	return false
}

func TestCleanupSessionReportRBAC_NotFoundIsNoop(t *testing.T) {
	scheme := newRBACScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	ctx := context.Background()

	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "diag", Namespace: "team-a", UID: "sess-abc"},
	}
	if err := cleanupSessionReportRBAC(ctx, c, s); err != nil {
		t.Fatalf("cleanup on empty: %v", err)
	}
}

func TestReportRefResource(t *testing.T) {
	cm := &corev1.LocalObjectReference{Name: "r"}
	sec := &corev1.LocalObjectReference{Name: "r"}
	cases := []struct {
		name                   string
		ref                    *podtracev1alpha1.ReportReference
		wantResource, wantName string
	}{
		{"nil", nil, "", ""},
		{"empty", &podtracev1alpha1.ReportReference{}, "", ""},
		{"configMap", &podtracev1alpha1.ReportReference{ConfigMap: cm}, "configmaps", "r"},
		{"secret", &podtracev1alpha1.ReportReference{Secret: sec}, "secrets", "r"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, n := reportRefResource(tc.ref)
			if r != tc.wantResource || n != tc.wantName {
				t.Errorf("got (%q,%q) want (%q,%q)", r, n, tc.wantResource, tc.wantName)
			}
		})
	}
}

func TestReportToSpecFromReportRef(t *testing.T) {
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "diag", Namespace: "team-a"},
	}
	if got := reportToSpecFromReportRef(s); got != "" {
		t.Errorf("no-ref should be empty: %q", got)
	}
	s.Spec.ReportRef = &podtracev1alpha1.ReportReference{
		ConfigMap: &corev1.LocalObjectReference{Name: "rpt"},
	}
	if got := reportToSpecFromReportRef(s); got != "configmap/team-a/rpt" {
		t.Errorf("configmap spec: %q", got)
	}
	s.Spec.ReportRef = &podtracev1alpha1.ReportReference{
		Secret: &corev1.LocalObjectReference{Name: "rpt"},
	}
	if got := reportToSpecFromReportRef(s); got != "secret/team-a/rpt" {
		t.Errorf("secret spec: %q", got)
	}
}
