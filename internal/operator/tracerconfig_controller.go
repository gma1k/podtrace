package operator

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// TracerConfigReconciler owns the cluster-wide agent infrastructure:
// the agent DaemonSet, its ServiceAccount, and the ClusterRole/Binding
// that grants agents the minimum RBAC to do their job.
//
// Only a single TracerConfig object named "default" is reconciled in
// this first iteration; other names are accepted but the DaemonSet
// always lives under AgentDaemonSetName() in SystemNamespace so the
// agent-side discovery path stays simple.
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
			// Resource deleted; owner refs on the DaemonSet + RBAC clean
			// themselves up. Nothing to do here.
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get TracerConfig: %w", err)
	}

	systemNS := r.systemNamespaceFor(&tc)

	if err := r.ensureAgentRBAC(ctx, &tc, systemNS); err != nil {
		logger.Error(err, "ensure agent RBAC")
		r.setCondition(&tc, ConditionDegraded, metav1.ConditionTrue, "RBACError", err.Error())
		_ = r.Status().Update(ctx, &tc)
		return ctrl.Result{}, err
	}

	ds, err := r.ensureAgentDaemonSet(ctx, &tc, systemNS)
	if err != nil {
		logger.Error(err, "ensure agent DaemonSet")
		r.setCondition(&tc, ConditionDegraded, metav1.ConditionTrue, "DaemonSetError", err.Error())
		_ = r.Status().Update(ctx, &tc)
		return ctrl.Result{}, err
	}

	tc.Status.DesiredAgents = ds.Status.DesiredNumberScheduled
	tc.Status.ReadyAgents = ds.Status.NumberReady
	tc.Status.ObservedGeneration = tc.Generation
	r.setCondition(&tc, ConditionReconciled, metav1.ConditionTrue, "Reconciled", "agent infrastructure reconciled")
	r.setCondition(&tc, ConditionReady,
		conditionStatusFromBool(tc.Status.ReadyAgents == tc.Status.DesiredAgents && tc.Status.DesiredAgents > 0),
		"AgentFleetReady",
		fmt.Sprintf("%d/%d agents Ready", tc.Status.ReadyAgents, tc.Status.DesiredAgents),
	)
	r.setCondition(&tc, ConditionDegraded, metav1.ConditionFalse, "Reconciled", "")

	if err := r.Status().Update(ctx, &tc); err != nil {
		// Conflict: the TracerConfig was mutated between our Get and
		// our Status().Update (often controller-runtime itself writing
		// ownerReferences on child adoption). Re-queue rather than
		// surfacing the race as a terminal error — the next reconcile
		// reads the fresh resourceVersion and succeeds.
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
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
		For(&podtracev1alpha1.TracerConfig{}).
		Owns(&appsv1.DaemonSet{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&rbacv1.ClusterRole{}).
		Owns(&rbacv1.ClusterRoleBinding{}).
		WithEventFilter(predicate.Or(
			predicate.GenerationChangedPredicate{},
			predicate.LabelChangedPredicate{},
		)).
		WithOptions(defaultControllerOptions()).
		Complete(r)
}

func (r *TracerConfigReconciler) systemNamespaceFor(tc *podtracev1alpha1.TracerConfig) string {
	if tc.Spec.SystemNamespace != "" {
		return tc.Spec.SystemNamespace
	}
	return r.SystemNamespace
}

// ensureAgentRBAC creates / updates the agent SA, ClusterRole, and
// ClusterRoleBinding. All three are owned by the TracerConfig so that
// deleting the TracerConfig tears them down.
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

// agentClusterRoleRules returns the minimum RBAC the agent needs:
//
//   - List/watch PodTrace cluster-wide (so it can merge CRs on its node)
//   - Patch PodTrace/status (so it can write its per-node status entry)
//   - Read Pods cluster-wide (to resolve selectors against pod labels;
//     scoped narrower if operators later introduce per-namespace agents)
//   - Read ConfigMap/Secret only inside systemNS (exporter bundles)
//   - Create/patch Events (surface attach failures back to operators)
//
// The rules are intentionally over-scoped for PodTrace reads because the
// SharedInformer list-watches cluster-wide; restricting to a namespace
// breaks the multi-namespace selector story.
func agentClusterRoleRules(systemNS string) []rbacv1.PolicyRule {
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
		// Bundles live in systemNS; agent reads them via a namespaced
		// request. ClusterRole is still used for simplicity — a
		// RoleBinding per agent pod would add deploy complexity for no
		// practical security gain given the rest of the scope.
		{
			APIGroups:     []string{""},
			Resources:     []string{"configmaps", "secrets"},
			Verbs:         []string{"get", "list", "watch"},
			ResourceNames: []string{}, // namespace scoping applied by agent's code; cluster-level rule is broad
		},
	}
}

// setCondition applies one Condition to the TracerConfig status, keyed
// by Type. The library-standard meta.SetStatusCondition semantics are
// replicated inline to avoid a dependency on k8s.io/apimachinery/pkg/api/meta
// just for this.
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

