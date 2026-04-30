package operator

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func ensureSessionServiceAccount(ctx context.Context, c client.Client, systemNS string) error {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      SessionServiceAccountName(),
			Namespace: systemNS,
		},
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, c, sa, func() error {
		sa.Labels = mergeLabels(sa.Labels, map[string]string{
			LabelManagedBy: ManagedByValue,
			LabelComponent: ComponentSession,
		})
		return nil
	}); err != nil {
		return fmt.Errorf("ensure session SA: %w", err)
	}
	return nil
}

// ensureSessionReportRBAC provisions per-session RBAC in the user
// namespace. The session SA always needs pods + events read (the CLI
// resolves pod → container → cgroup on startup); when spec.reportRef
// is set we additionally grant a resourceNames-scoped get/update/create
// on the specific ConfigMap or Secret the CLI will patch.
func ensureSessionReportRBAC(ctx context.Context, c client.Client, s *podtracev1alpha1.PodTraceSession, systemNS string) error {
	roleName := SessionReportRoleName(s.UID)
	bindingName := SessionReportRoleBindingName(s.UID)

	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: roleName, Namespace: s.Namespace},
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, c, role, func() error {
		role.Labels = mergeLabels(role.Labels, map[string]string{
			LabelManagedBy:   ManagedByValue,
			LabelComponent:   ComponentSession,
			LabelSessionName: s.Name,
			LabelSessionNS:   s.Namespace,
		})
		role.Rules = buildSessionReportRules(s.Spec.ReportRef)
		return nil
	}); err != nil {
		return fmt.Errorf("ensure session report Role: %w", err)
	}

	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: bindingName, Namespace: s.Namespace},
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, c, binding, func() error {
		binding.Labels = mergeLabels(binding.Labels, map[string]string{
			LabelManagedBy:   ManagedByValue,
			LabelComponent:   ComponentSession,
			LabelSessionName: s.Name,
			LabelSessionNS:   s.Namespace,
		})
		binding.RoleRef = rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     roleName,
		}
		binding.Subjects = []rbacv1.Subject{{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      SessionServiceAccountName(),
			Namespace: systemNS,
		}}
		return nil
	}); err != nil {
		return fmt.Errorf("ensure session report RoleBinding: %w", err)
	}
	return nil
}

// cleanupSessionReportRBAC deletes the per-session Role+RoleBinding in
// the user namespace. Called from the session finalizer path. NotFound
// is non-fatal — the session may have been created without a reportRef.
func cleanupSessionReportRBAC(ctx context.Context, c client.Client, s *podtracev1alpha1.PodTraceSession) error {
	objects := []client.Object{
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{
			Name: SessionReportRoleBindingName(s.UID), Namespace: s.Namespace,
		}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{
			Name: SessionReportRoleName(s.UID), Namespace: s.Namespace,
		}},
	}
	for _, obj := range objects {
		if err := c.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete session RBAC %T: %w", obj, err)
		}
	}
	return nil
}

func buildSessionReportRules(ref *podtracev1alpha1.ReportReference) []rbacv1.PolicyRule {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"events"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"events.k8s.io"},
			Resources: []string{"events"},
			Verbs:     []string{"get", "list", "watch"},
		},
	}
	resource, name := reportRefResource(ref)
	if resource == "" || name == "" {
		return rules
	}
	// Kubernetes evaluates "create" at the collection level: a
	// resourceNames-scoped rule does not cover first-time creation,
	// so the create verb needs a separate unscoped rule on the same
	// resource kind. Read/update stay narrowed by resourceNames.
	rules = append(rules,
		rbacv1.PolicyRule{
			APIGroups:     []string{""},
			Resources:     []string{resource},
			ResourceNames: []string{name},
			Verbs:         []string{"get", "update"},
		},
		rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{resource},
			Verbs:     []string{"create"},
		},
	)
	return rules
}

// reportRefResource decodes spec.reportRef into the (resource, name)
// tuple the RBAC grant needs. Returns empty strings when no supported
// sink is set (including ObjectStore, which the webhook rejects today).
func reportRefResource(ref *podtracev1alpha1.ReportReference) (string, string) {
	switch {
	case ref == nil:
		return "", ""
	case ref.ConfigMap != nil && ref.ConfigMap.Name != "":
		return "configmaps", ref.ConfigMap.Name
	case ref.Secret != nil && ref.Secret.Name != "":
		return "secrets", ref.Secret.Name
	}
	return "", ""
}

// reportToSpecFromReportRef renders the session's reportRef into the
// kind/namespace/name form the CLI's --report-to flag parses. Used by
// the Job spec builder to wire the flag. Returns empty string when no
// CLI-uploadable sink is set.
func reportToSpecFromReportRef(s *podtracev1alpha1.PodTraceSession) string {
	if s == nil || s.Spec.ReportRef == nil {
		return ""
	}
	switch {
	case s.Spec.ReportRef.ConfigMap != nil && s.Spec.ReportRef.ConfigMap.Name != "":
		return "configmap/" + s.Namespace + "/" + s.Spec.ReportRef.ConfigMap.Name
	case s.Spec.ReportRef.Secret != nil && s.Spec.ReportRef.Secret.Name != "":
		return "secret/" + s.Namespace + "/" + s.Spec.ReportRef.Secret.Name
	}
	return ""
}