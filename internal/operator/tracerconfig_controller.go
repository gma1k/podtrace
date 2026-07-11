package operator

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// TracerConfigReconciler owns the cluster-wide agent infrastructure:
// the agent DaemonSet, its ServiceAccount, and the ClusterRole/Binding
// that grants agents the minimum RBAC to do their job.
type TracerConfigReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	SystemNamespace string
}

// +kubebuilder:rbac:groups=podtrace.io,resources=tracerconfigs,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=podtrace.io,resources=tracerconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=podtrace.io,resources=tracerconfigs/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles;clusterrolebindings,verbs=get;list;watch;create;update;patch;delete

// Reconcile ensures the agent DaemonSet and its RBAC match spec.
// Idempotent; re-queues on transient API errors.
func (r *TracerConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("tracerconfig", req.Name)

	var tc podtracev1alpha1.TracerConfig
	if err := r.Get(ctx, req.NamespacedName, &tc); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get TracerConfig: %w", err)
	}

	if tc.Name != DefaultTracerConfigName {
		r.setCondition(&tc, ConditionDegraded, metav1.ConditionTrue, "NotDefaultTracerConfig",
			fmt.Sprintf("only the %q TracerConfig manages the agent DaemonSet; this resource is inert", DefaultTracerConfigName))
		r.setCondition(&tc, ConditionReady, metav1.ConditionFalse, "NotDefaultTracerConfig", "inert non-default TracerConfig")
		if err := r.Status().Update(ctx, &tc); err != nil && !apierrors.IsConflict(err) {
			return ctrl.Result{}, fmt.Errorf("update status: %w", err)
		}
		return ctrl.Result{}, nil
	}

	systemNS := r.systemNamespaceFor(&tc)

	if err := r.ensureAgentRBAC(ctx, &tc, systemNS); err != nil {
		logger.Error(err, "ensure agent RBAC")
		r.setCondition(&tc, ConditionDegraded, metav1.ConditionTrue, "RBACError", err.Error())
		if uerr := r.Status().Update(ctx, &tc); uerr != nil && !apierrors.IsConflict(uerr) {
			logger.Error(uerr, "update Degraded status after RBAC error")
		}
		return ctrl.Result{}, err
	}

	ds, err := r.ensureAgentDaemonSet(ctx, &tc, systemNS)
	if err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{RequeueAfter: time.Second}, nil
		}
		logger.Error(err, "ensure agent DaemonSet")
		r.setCondition(&tc, ConditionDegraded, metav1.ConditionTrue, "DaemonSetError", err.Error())
		if uerr := r.Status().Update(ctx, &tc); uerr != nil && !apierrors.IsConflict(uerr) {
			logger.Error(uerr, "update Degraded status after DaemonSet error")
		}
		return ctrl.Result{}, err
	}

	if err := r.cleanupStaleAgentNamespaces(ctx, systemNS); err != nil {
		logger.Error(err, "cleanup stale agent namespaces")
	}

	tc.Status.DesiredAgents = ds.Status.DesiredNumberScheduled
	tc.Status.ReadyAgents = ds.Status.NumberReady
	tc.Status.ActiveSessions = r.countActiveSessions(ctx)
	tc.Status.ObservedGeneration = tc.Generation

	if tc.Spec.BTFMode == podtracev1alpha1.BTFModeEmbedded {
		logger.Info("spec.btfMode=embedded is not implemented; agent uses host BTF (auto)")
	}
	r.setCondition(&tc, ConditionReconciled, metav1.ConditionTrue, "Reconciled", "agent infrastructure reconciled")
	r.setCondition(&tc, ConditionReady,
		conditionStatusFromBool(tc.Status.ReadyAgents == tc.Status.DesiredAgents && tc.Status.DesiredAgents > 0),
		"AgentFleetReady",
		fmt.Sprintf("%d/%d agents Ready", tc.Status.ReadyAgents, tc.Status.DesiredAgents),
	)
	r.setCondition(&tc, ConditionDegraded, metav1.ConditionFalse, "Reconciled", "")

	if err := r.Status().Update(ctx, &tc); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{RequeueAfter: time.Second}, nil
		}
		return ctrl.Result{}, fmt.Errorf("update status: %w", err)
	}
	return ctrl.Result{}, nil
}

// SetupWithManager registers the reconciler, declaring owned resources
// so controller-runtime requeues the TracerConfig whenever an owned
// resource's status changes.
func (r *TracerConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("tracerconfig").
		For(&podtracev1alpha1.TracerConfig{}, builder.WithPredicates(predicate.Or(
			predicate.GenerationChangedPredicate{},
			predicate.LabelChangedPredicate{},
		))).
		Owns(&appsv1.DaemonSet{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&rbacv1.ClusterRole{}).
		Owns(&rbacv1.ClusterRoleBinding{}).
		Owns(&rbacv1.Role{}).
		Owns(&rbacv1.RoleBinding{}).
		Watches(&podtracev1alpha1.PodTraceSession{},
			handler.EnqueueRequestsFromMapFunc(func(context.Context, client.Object) []reconcile.Request {
				return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: DefaultTracerConfigName}}}
			})).
		WithOptions(defaultControllerOptions()).
		Complete(r)
}

func (r *TracerConfigReconciler) systemNamespaceFor(tc *podtracev1alpha1.TracerConfig) string {
	if tc.Spec.SystemNamespace != "" {
		return tc.Spec.SystemNamespace
	}
	return r.SystemNamespace
}

// countActiveSessions reports how many PodTraceSessions are not yet terminal
// (Pending or Running), populating status.activeSessions, which was declared
// (and printed as the "Sessions" column) but never set.
func (r *TracerConfigReconciler) countActiveSessions(ctx context.Context) int32 {
	var sessions podtracev1alpha1.PodTraceSessionList
	if err := r.List(ctx, &sessions); err != nil {
		return 0
	}
	var active int32
	for i := range sessions.Items {
		switch sessions.Items[i].Status.State {
		case podtracev1alpha1.SessionStateCompleted, podtracev1alpha1.SessionStateFailed:
		default:
			active++
		}
	}
	return active
}

// ensureAgentRBAC creates / updates the agent SA, ClusterRole, and
// ClusterRoleBinding.
func (r *TracerConfigReconciler) ensureAgentRBAC(ctx context.Context, tc *podtracev1alpha1.TracerConfig, systemNS string) error {
	sa := &corev1.ServiceAccount{
		ObjectMeta: ManagedObjectMeta(AgentServiceAccountName(), systemNS, ComponentAgent, nil),
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, sa, func() error {
		sa.Labels = mergeLabels(sa.Labels, map[string]string{LabelManagedBy: ManagedByValue, LabelComponent: ComponentAgent})
		return controllerutil.SetControllerReference(tc, sa, r.Scheme)
	}); err != nil {
		return fmt.Errorf("ServiceAccount: %w", err)
	}

	cr := &rbacv1.ClusterRole{
		ObjectMeta: ManagedObjectMeta(AgentClusterRoleName(), "", ComponentAgent, nil),
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, cr, func() error {
		cr.Labels = mergeLabels(cr.Labels, map[string]string{LabelManagedBy: ManagedByValue, LabelComponent: ComponentAgent})
		cr.Rules = agentClusterRoleRules(systemNS)
		return controllerutil.SetControllerReference(tc, cr, r.Scheme)
	}); err != nil {
		return fmt.Errorf("ClusterRole: %w", err)
	}

	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: ManagedObjectMeta(AgentClusterRoleBindingName(), "", ComponentAgent, nil),
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, crb, func() error {
		crb.Labels = mergeLabels(crb.Labels, map[string]string{LabelManagedBy: ManagedByValue, LabelComponent: ComponentAgent})
		crb.RoleRef = rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     AgentClusterRoleName(),
		}
		crb.Subjects = []rbacv1.Subject{{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      AgentServiceAccountName(),
			Namespace: systemNS,
		}}
		return controllerutil.SetControllerReference(tc, crb, r.Scheme)
	}); err != nil {
		return fmt.Errorf("ClusterRoleBinding: %w", err)
	}

	role := &rbacv1.Role{
		ObjectMeta: ManagedObjectMeta(AgentBundleRoleName(), systemNS, ComponentAgent, nil),
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, role, func() error {
		role.Labels = mergeLabels(role.Labels, map[string]string{LabelManagedBy: ManagedByValue, LabelComponent: ComponentAgent})
		role.Rules = []rbacv1.PolicyRule{{
			APIGroups: []string{""},
			Resources: []string{"configmaps", "secrets"},
			Verbs:     []string{"get", "list", "watch"},
		}}
		return controllerutil.SetControllerReference(tc, role, r.Scheme)
	}); err != nil {
		return fmt.Errorf("agent bundle Role: %w", err)
	}

	rb := &rbacv1.RoleBinding{
		ObjectMeta: ManagedObjectMeta(AgentBundleRoleBindingName(), systemNS, ComponentAgent, nil),
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, rb, func() error {
		rb.Labels = mergeLabels(rb.Labels, map[string]string{LabelManagedBy: ManagedByValue, LabelComponent: ComponentAgent})
		rb.RoleRef = rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     AgentBundleRoleName(),
		}
		rb.Subjects = []rbacv1.Subject{{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      AgentServiceAccountName(),
			Namespace: systemNS,
		}}
		return controllerutil.SetControllerReference(tc, rb, r.Scheme)
	}); err != nil {
		return fmt.Errorf("agent bundle RoleBinding: %w", err)
	}
	return nil
}

// cleanupStaleAgentNamespaces deletes agent DaemonSets (and their namespaced
// RBAC companions) left behind in OTHER namespaces after a
// spec.systemNamespace change.
func (r *TracerConfigReconciler) cleanupStaleAgentNamespaces(ctx context.Context, currentNS string) error {
	agentLabels := client.MatchingLabels{
		LabelManagedBy: ManagedByValue,
		LabelComponent: ComponentAgent,
	}

	var dsList appsv1.DaemonSetList
	if err := r.List(ctx, &dsList, agentLabels); err != nil {
		return fmt.Errorf("list agent DaemonSets: %w", err)
	}
	for i := range dsList.Items {
		ds := &dsList.Items[i]
		if ds.Namespace == currentNS {
			continue
		}
		if err := r.Delete(ctx, ds); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete stale agent DaemonSet %s/%s: %w", ds.Namespace, ds.Name, err)
		}
	}

	var saList corev1.ServiceAccountList
	if err := r.List(ctx, &saList, agentLabels); err != nil {
		return fmt.Errorf("list agent ServiceAccounts: %w", err)
	}
	for i := range saList.Items {
		sa := &saList.Items[i]
		if sa.Namespace == currentNS {
			continue
		}
		if err := r.Delete(ctx, sa); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete stale agent ServiceAccount %s/%s: %w", sa.Namespace, sa.Name, err)
		}
	}

	var roleList rbacv1.RoleList
	if err := r.List(ctx, &roleList, agentLabels); err != nil {
		return fmt.Errorf("list agent Roles: %w", err)
	}
	for i := range roleList.Items {
		role := &roleList.Items[i]
		if role.Namespace == currentNS {
			continue
		}
		if err := r.Delete(ctx, role); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete stale agent Role %s/%s: %w", role.Namespace, role.Name, err)
		}
	}

	var rbList rbacv1.RoleBindingList
	if err := r.List(ctx, &rbList, agentLabels); err != nil {
		return fmt.Errorf("list agent RoleBindings: %w", err)
	}
	for i := range rbList.Items {
		rb := &rbList.Items[i]
		if rb.Namespace == currentNS {
			continue
		}
		if err := r.Delete(ctx, rb); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete stale agent RoleBinding %s/%s: %w", rb.Namespace, rb.Name, err)
		}
	}
	return nil
}

// ensureAgentDaemonSet creates / updates the DaemonSet, returning its
// current status so Reconcile can roll it up.
func (r *TracerConfigReconciler) ensureAgentDaemonSet(ctx context.Context, tc *podtracev1alpha1.TracerConfig, systemNS string) (*appsv1.DaemonSet, error) {
	ds := &appsv1.DaemonSet{
		ObjectMeta: ManagedObjectMeta(AgentDaemonSetName(), systemNS, ComponentAgent, map[string]string{
			LabelTracerConfig: tc.Name,
		}),
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, ds, func() error {
		ds.Labels = mergeLabels(ds.Labels, map[string]string{
			LabelManagedBy:    ManagedByValue,
			LabelComponent:    ComponentAgent,
			LabelTracerConfig: tc.Name,
		})
		ds.Spec = buildAgentDaemonSetSpec(tc, systemNS)
		return controllerutil.SetControllerReference(tc, ds, r.Scheme)
	}); err != nil {
		return nil, err
	}
	return ds, nil
}

func agentClusterRoleRules(systemNS string) []rbacv1.PolicyRule {
	_ = systemNS
	return []rbacv1.PolicyRule{
		{
			APIGroups: []string{"podtrace.io"},
			Resources: []string{"podtraces"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{"podtrace.io"},
			Resources: []string{"podtraces/status"},
			Verbs:     []string{"get", "update", "patch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list", "watch"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"events"},
			Verbs:     []string{"create", "patch"},
		},
	}
}

// setCondition applies one Condition to the TracerConfig status, keyed
// by Type.
func (r *TracerConfigReconciler) setCondition(tc *podtracev1alpha1.TracerConfig, condType string, status metav1.ConditionStatus, reason, message string) {
	tc.Status.Conditions = upsertCondition(tc.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
		ObservedGeneration: tc.Generation,
	})
}
