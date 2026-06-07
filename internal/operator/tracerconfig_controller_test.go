//go:build envtest
// +build envtest

package operator

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func TestTracerConfigReconciler_EnvtestLifecycle(t *testing.T) {
	scheme, c, _ := setupSharedEnvtest(t)
	systemNS := ensureDedicatedSystemNamespace(t, c, "lifecycle")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tcObj := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "lifecycle"},
		Spec: podtracev1alpha1.TracerConfigSpec{
			Image:           "ghcr.io/gma1k/podtrace:test",
			SystemNamespace: systemNS,
		},
	}
	if err := c.Create(ctx, tcObj); err != nil {
		t.Fatalf("create TracerConfig: %v", err)
	}
	t.Cleanup(func() {
		// Best-effort cleanup for cluster-scoped resources envtest does
		// not garbage-collect automatically.
		_ = c.Delete(ctx, &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: AgentClusterRoleBindingName()}})
		_ = c.Delete(ctx, &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: AgentClusterRoleName()}})
	})

	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: systemNS}

	// --- create ----------------------------------------------------
	reconcileUntil(t, 10*time.Second,
		func() error {
			var ds appsv1.DaemonSet
			return c.Get(ctx, types.NamespacedName{Name: AgentDaemonSetName(), Namespace: systemNS}, &ds)
		},
		func() error {
			_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "lifecycle"}})
			return err
		},
	)

	var ds appsv1.DaemonSet
	if err := c.Get(ctx, types.NamespacedName{Name: AgentDaemonSetName(), Namespace: systemNS}, &ds); err != nil {
		t.Fatalf("DaemonSet missing: %v", err)
	}
	if !ownedByTracerConfig(&ds.ObjectMeta, tcObj.Name) {
		t.Errorf("DaemonSet has no ownerRef to TracerConfig: %+v", ds.OwnerReferences)
	}
	if ds.Spec.Template.Spec.Containers[0].Image != tcObj.Spec.Image {
		t.Errorf("image not propagated: %q", ds.Spec.Template.Spec.Containers[0].Image)
	}

	var cr rbacv1.ClusterRole
	if err := c.Get(ctx, types.NamespacedName{Name: AgentClusterRoleName()}, &cr); err != nil {
		t.Fatalf("ClusterRole missing: %v", err)
	}
	if !hasRule(&cr, "podtrace.io", "podtraces") {
		t.Error("ClusterRole missing rule for podtrace.io/podtraces")
	}

	var crb rbacv1.ClusterRoleBinding
	if err := c.Get(ctx, types.NamespacedName{Name: AgentClusterRoleBindingName()}, &crb); err != nil {
		t.Fatalf("ClusterRoleBinding missing: %v", err)
	}
	if len(crb.Subjects) != 1 || crb.Subjects[0].Name != AgentServiceAccountName() {
		t.Errorf("ClusterRoleBinding subjects wrong: %+v", crb.Subjects)
	}

	if hasRule(&cr, "", "configmaps") || hasRule(&cr, "", "secrets") {
		t.Errorf("ClusterRole leaks cluster-wide configmap/secret read: %+v", cr.Rules)
	}

	var bundleRole rbacv1.Role
	if err := c.Get(ctx, types.NamespacedName{Name: AgentBundleRoleName(), Namespace: systemNS}, &bundleRole); err != nil {
		t.Fatalf("agent bundle Role missing in %s: %v", systemNS, err)
	}
	if !ruleHas(bundleRole.Rules, "", "configmaps") || !ruleHas(bundleRole.Rules, "", "secrets") {
		t.Errorf("agent bundle Role missing configmap/secret rules: %+v", bundleRole.Rules)
	}

	var bundleRB rbacv1.RoleBinding
	if err := c.Get(ctx, types.NamespacedName{Name: AgentBundleRoleBindingName(), Namespace: systemNS}, &bundleRB); err != nil {
		t.Fatalf("agent bundle RoleBinding missing: %v", err)
	}
	if bundleRB.RoleRef.Kind != "Role" || bundleRB.RoleRef.Name != AgentBundleRoleName() {
		t.Errorf("bundle RoleBinding.roleRef wrong: %+v", bundleRB.RoleRef)
	}
	if len(bundleRB.Subjects) != 1 || bundleRB.Subjects[0].Name != AgentServiceAccountName() ||
		bundleRB.Subjects[0].Namespace != systemNS {
		t.Errorf("bundle RoleBinding.subjects wrong: %+v", bundleRB.Subjects)
	}

	// --- delete ---------------------------------------------------
	if err := c.Delete(ctx, tcObj); err != nil {
		t.Fatalf("delete TracerConfig: %v", err)
	}
	// Post-delete reconcile should be a clean no-op (not-found path).
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: tcObj.Name}}); err != nil {
		t.Fatalf("post-delete reconcile should be nil: %v", err)
	}
	if err := c.Get(ctx, types.NamespacedName{Name: tcObj.Name}, &podtracev1alpha1.TracerConfig{}); !apierrors.IsNotFound(err) {
		t.Errorf("TracerConfig still present after delete: %v", err)
	}
}

func ownedByTracerConfig(meta *metav1.ObjectMeta, tcName string) bool {
	for _, o := range meta.OwnerReferences {
		if o.Kind == "TracerConfig" && o.Name == tcName {
			return true
		}
	}
	return false
}

func hasRule(cr *rbacv1.ClusterRole, apiGroup, resource string) bool {
	return ruleHas(cr.Rules, apiGroup, resource)
}

func ruleHas(rules []rbacv1.PolicyRule, apiGroup, resource string) bool {
	for _, r := range rules {
		ag := false
		for _, g := range r.APIGroups {
			if g == apiGroup {
				ag = true
				break
			}
		}
		if !ag {
			continue
		}
		for _, res := range r.Resources {
			if res == resource {
				return true
			}
		}
	}
	return false
}