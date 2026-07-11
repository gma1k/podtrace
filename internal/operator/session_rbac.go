package operator

import (
	"context"
	"fmt"
	"sort"

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
// namespace.
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

// sessionRBACLabels are the labels every per-session RBAC object carries, so
// the cross-namespace pod-read grants can be located and cleaned up by label.
func sessionRBACLabels(s *podtracev1alpha1.PodTraceSession) map[string]string {
	return map[string]string{
		LabelManagedBy:   ManagedByValue,
		LabelComponent:   ComponentSession,
		LabelSessionName: s.Name,
		LabelSessionNS:   s.Namespace,
	}
}

// sessionPodNamespaces returns the namespaces the in-Job CLI reads pods from
// BEYOND the session's own namespace: the resolved namespaceSelector allowlist
// (when spec.selector is set) plus any cross-namespace spec.podRefs.
func sessionPodNamespaces(s *podtracev1alpha1.PodTraceSession, targetNamespaces []string) []string {
	set := map[string]struct{}{}
	if s.Spec.Selector != nil {
		for _, ns := range targetNamespaces {
			if ns != "" && ns != s.Namespace {
				set[ns] = struct{}{}
			}
		}
	}
	for _, ref := range s.Spec.PodRefs {
		if ref.Namespace != "" && ref.Namespace != s.Namespace {
			set[ref.Namespace] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for ns := range set {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}

// ensureSessionPodReadRBAC grants the session SA pods+events read in each
// extra namespace a cross-namespace session targets.
func ensureSessionPodReadRBAC(ctx context.Context, c client.Client, s *podtracev1alpha1.PodTraceSession, namespaces []string, systemNS string) error {
	for _, ns := range namespaces {
		role := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: SessionPodReadRoleName(s.UID), Namespace: ns}}
		if _, err := controllerutil.CreateOrUpdate(ctx, c, role, func() error {
			role.Labels = mergeLabels(role.Labels, sessionRBACLabels(s))
			role.Rules = []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list", "watch"}},
				{APIGroups: []string{""}, Resources: []string{"events"}, Verbs: []string{"get", "list", "watch"}},
			}
			return nil
		}); err != nil {
			return fmt.Errorf("ensure session pod-read Role in %s: %w", ns, err)
		}

		binding := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: SessionPodReadRoleBindingName(s.UID), Namespace: ns}}
		if _, err := controllerutil.CreateOrUpdate(ctx, c, binding, func() error {
			binding.Labels = mergeLabels(binding.Labels, sessionRBACLabels(s))
			binding.RoleRef = rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "Role",
				Name:     SessionPodReadRoleName(s.UID),
			}
			binding.Subjects = []rbacv1.Subject{{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      SessionServiceAccountName(),
				Namespace: systemNS,
			}}
			return nil
		}); err != nil {
			return fmt.Errorf("ensure session pod-read RoleBinding in %s: %w", ns, err)
		}
	}
	return nil
}

// cleanupSessionPodReadRBAC deletes the cross-namespace pod-read Role+RoleBinding
// for a session.
func cleanupSessionPodReadRBAC(ctx context.Context, c client.Client, s *podtracev1alpha1.PodTraceSession) error {
	sel := client.MatchingLabels(sessionRBACLabels(s))

	var bindings rbacv1.RoleBindingList
	if err := c.List(ctx, &bindings, sel); err != nil {
		return fmt.Errorf("list session pod-read RoleBindings: %w", err)
	}
	for i := range bindings.Items {
		if bindings.Items[i].Name != SessionPodReadRoleBindingName(s.UID) {
			continue
		}
		if err := c.Delete(ctx, &bindings.Items[i]); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete session pod-read RoleBinding %s/%s: %w",
				bindings.Items[i].Namespace, bindings.Items[i].Name, err)
		}
	}

	var roles rbacv1.RoleList
	if err := c.List(ctx, &roles, sel); err != nil {
		return fmt.Errorf("list session pod-read Roles: %w", err)
	}
	for i := range roles.Items {
		if roles.Items[i].Name != SessionPodReadRoleName(s.UID) {
			continue
		}
		if err := c.Delete(ctx, &roles.Items[i]); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete session pod-read Role %s/%s: %w",
				roles.Items[i].Namespace, roles.Items[i].Name, err)
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
	}
	resource, name := reportRefResource(ref)
	if resource == "" || name == "" {
		return rules
	}
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
// form the CLI's --report-to flag parses. Returns empty string when no
func reportToSpecFromReportRef(s *podtracev1alpha1.PodTraceSession) string {
	if s == nil || s.Spec.ReportRef == nil {
		return ""
	}
	switch {
	case s.Spec.ReportRef.ConfigMap != nil && s.Spec.ReportRef.ConfigMap.Name != "":
		return "configmap/" + s.Namespace + "/" + s.Spec.ReportRef.ConfigMap.Name
	case s.Spec.ReportRef.Secret != nil && s.Spec.ReportRef.Secret.Name != "":
		return "secret/" + s.Namespace + "/" + s.Spec.ReportRef.Secret.Name
	case s.Spec.ReportRef.ObjectStore != nil && s.Spec.ReportRef.ObjectStore.URI != "":
		return s.Spec.ReportRef.ObjectStore.URI
	}
	return ""
}
