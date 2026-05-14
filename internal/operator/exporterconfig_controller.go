package operator

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// ExporterConfigReconciler populates an ExporterConfig's status:
//
//   - Ready=true when spec variant validates AND every referenced Secret
//     (and required key, if any) exists.
//   - ReferencedBy = #PodTraces + #non-terminal PodTraceSessions in the
//     same namespace whose .spec.exporterRef.name matches.
//   - Referenced condition mirrors ReferencedBy > 0.
type ExporterConfigReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reason strings for the Ready / Referenced conditions. Stable
// contract — operators match against these in alerts / kubectl wait.
const (
	ecReasonSecretsResolved  = "SecretsResolved"
	ecReasonSecretMissing    = "SecretMissing"
	ecReasonSecretKeyMissing = "SecretKeyMissing"
	ecReasonInvalidSpec      = "InvalidSpec"
	ecReasonTransientError   = "TransientError"
	ecReasonReferenced       = "Referenced"
	ecReasonUnreferenced     = "Unreferenced"

	ecMaxConditionMessageLen = 256
)

// Field-indexer keys. Registered against PodTrace and PodTraceSession
// in registerExporterConfigIndexers — reverse lookup so the
// reconciler can ask "which PT/PTS objects point at this EC name?"
// without listing the entire namespace.
const (
	IndexFieldPodTraceExporterRef        = "spec.exporterRef.name"
	IndexFieldPodTraceSessionExporterRef = "spec.exporterRef.name"
)

// +kubebuilder:rbac:groups=podtrace.io,resources=exporterconfigs,verbs=get;list;watch
// +kubebuilder:rbac:groups=podtrace.io,resources=exporterconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch

func (r *ExporterConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var ec podtracev1alpha1.ExporterConfig
	if err := r.Get(ctx, req.NamespacedName, &ec); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get ExporterConfig: %w", err)
	}

	orig := ec.DeepCopy()

	ready, readyStatus, readyReason, readyMessage := r.evaluateReadiness(ctx, &ec)

	refs, err := r.countReferences(ctx, &ec)
	if err != nil {
		// Listing failures are transient — keep the previous count
		// rather than zeroing it and triggering false alerts.
		logger.V(1).Info("count references failed; keeping previous count", "error", err)
		refs = ec.Status.ReferencedBy
	}

	ec.Status.ObservedGeneration = ec.Generation
	ec.Status.Ready = ready
	ec.Status.ReferencedBy = refs

	setCondition(&ec.Status.Conditions, ec.Generation, metav1.Condition{
		Type:    ConditionReady,
		Status:  readyStatus,
		Reason:  readyReason,
		Message: clampMessage(readyMessage),
	})

	if refs > 0 {
		setCondition(&ec.Status.Conditions, ec.Generation, metav1.Condition{
			Type:    ConditionReferenced,
			Status:  metav1.ConditionTrue,
			Reason:  ecReasonReferenced,
			Message: fmt.Sprintf("%d referent(s)", refs),
		})
	} else {
		setCondition(&ec.Status.Conditions, ec.Generation, metav1.Condition{
			Type:    ConditionReferenced,
			Status:  metav1.ConditionFalse,
			Reason:  ecReasonUnreferenced,
			Message: "no PodTrace or active PodTraceSession references this ExporterConfig",
		})
	}

	if statusEqual(orig.Status, ec.Status) {
		return ctrl.Result{}, nil
	}

	if err := r.Status().Patch(ctx, &ec, client.MergeFrom(orig)); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, fmt.Errorf("patch status: %w", err)
	}
	return ctrl.Result{}, nil
}

// evaluateReadiness returns (ready, conditionStatus, reason, message).
// The first failure short-circuits — operators see one actionable
// cause, not a list.
func (r *ExporterConfigReconciler) evaluateReadiness(ctx context.Context, ec *podtracev1alpha1.ExporterConfig) (bool, metav1.ConditionStatus, string, string) {
	logger := log.FromContext(ctx)

	if err := podtracev1alpha1.ValidateExporterConfigVariant(ec.Spec); err != nil {
		return false, metav1.ConditionFalse, ecReasonInvalidSpec, err.Error()
	}

	for _, ref := range collectSecretRefs(ec.Spec) {
		var sec corev1.Secret
		key := types.NamespacedName{Namespace: ec.Namespace, Name: ref.Name}
		if err := r.Get(ctx, key, &sec); err != nil {
			if apierrors.IsNotFound(err) {
				logger.V(1).Info("secret missing", "secret", key.String())
				return false, metav1.ConditionFalse, ecReasonSecretMissing,
					fmt.Sprintf("Secret %s/%s not found", ec.Namespace, ref.Name)
			}
			logger.V(1).Info("secret lookup transient error", "secret", key.String(), "error", err)
			return false, metav1.ConditionUnknown, ecReasonTransientError, err.Error()
		}
		if ref.Key != "" {
			if _, ok := sec.Data[ref.Key]; !ok {
				logger.V(1).Info("secret key missing", "secret", key.String(), "key", ref.Key)
				return false, metav1.ConditionFalse, ecReasonSecretKeyMissing,
					fmt.Sprintf("Secret %s/%s has no key %q", ec.Namespace, ref.Name, ref.Key)
			}
		}
	}

	return true, metav1.ConditionTrue, ecReasonSecretsResolved, "all referenced Secrets resolved"
}

// countReferences sums PodTraces and non-terminal PodTraceSessions in
// the EC's namespace whose .spec.exporterRef.name == ec.Name. Uses
// the field indexers registered in registerExporterConfigIndexers so
// the call cost is O(refs), not O(namespace).
func (r *ExporterConfigReconciler) countReferences(ctx context.Context, ec *podtracev1alpha1.ExporterConfig) (int32, error) {
	var ptList podtracev1alpha1.PodTraceList
	if err := r.List(ctx, &ptList,
		client.InNamespace(ec.Namespace),
		client.MatchingFields{IndexFieldPodTraceExporterRef: ec.Name},
	); err != nil {
		return 0, fmt.Errorf("list PodTrace: %w", err)
	}

	var ptsList podtracev1alpha1.PodTraceSessionList
	if err := r.List(ctx, &ptsList,
		client.InNamespace(ec.Namespace),
		client.MatchingFields{IndexFieldPodTraceSessionExporterRef: ec.Name},
	); err != nil {
		return 0, fmt.Errorf("list PodTraceSession: %w", err)
	}

	count := int32(len(ptList.Items))
	for i := range ptsList.Items {
		if !isSessionTerminal(ptsList.Items[i].Status.Phase) {
			count++
		}
	}
	return count, nil
}

func isSessionTerminal(p podtracev1alpha1.SessionPhase) bool {
	return p == podtracev1alpha1.SessionPhaseCompleted || p == podtracev1alpha1.SessionPhaseFailed
}

// SetupWithManager wires the controller's watches. Field indexers
// must already be installed (see registerExporterConfigIndexers).
func (r *ExporterConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("exporterconfig").
		For(&podtracev1alpha1.ExporterConfig{}).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.secretToExporterConfigs),
		).
		Watches(
			&podtracev1alpha1.PodTrace{},
			handler.EnqueueRequestsFromMapFunc(r.podTraceToExporterConfig),
		).
		Watches(
			&podtracev1alpha1.PodTraceSession{},
			handler.EnqueueRequestsFromMapFunc(r.sessionToExporterConfig),
		).
		WithOptions(defaultControllerOptions()).
		Complete(r)
}

// secretToExporterConfigs lists ECs in the Secret's namespace and
// emits a reconcile request for each whose spec references this
// Secret name. Same-namespace by construction — the EC types only
// allow LocalObjectReference / SecretKeySelector.
func (r *ExporterConfigReconciler) secretToExporterConfigs(ctx context.Context, obj client.Object) []reconcile.Request {
	sec, ok := obj.(*corev1.Secret)
	if !ok {
		return nil
	}
	var list podtracev1alpha1.ExporterConfigList
	if err := r.List(ctx, &list, client.InNamespace(sec.Namespace)); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range list.Items {
		ec := &list.Items[i]
		for _, ref := range collectSecretRefs(ec.Spec) {
			if ref.Name == sec.Name {
				reqs = append(reqs, reconcile.Request{
					NamespacedName: client.ObjectKey{Namespace: ec.Namespace, Name: ec.Name},
				})
				break
			}
		}
	}
	return reqs
}

func (r *ExporterConfigReconciler) podTraceToExporterConfig(_ context.Context, obj client.Object) []reconcile.Request {
	pt, ok := obj.(*podtracev1alpha1.PodTrace)
	if !ok {
		return nil
	}
	if pt.Spec.ExporterRef.Name == "" {
		return nil
	}
	return []reconcile.Request{{
		NamespacedName: client.ObjectKey{Namespace: pt.Namespace, Name: pt.Spec.ExporterRef.Name},
	}}
}

func (r *ExporterConfigReconciler) sessionToExporterConfig(_ context.Context, obj client.Object) []reconcile.Request {
	pts, ok := obj.(*podtracev1alpha1.PodTraceSession)
	if !ok {
		return nil
	}
	if pts.Spec.ExporterRef.Name == "" {
		return nil
	}
	return []reconcile.Request{{
		NamespacedName: client.ObjectKey{Namespace: pts.Namespace, Name: pts.Spec.ExporterRef.Name},
	}}
}

// registerExporterConfigIndexers installs the field indexers the
// ExporterConfig reconciler needs to look up referencing PodTrace and
// PodTraceSession objects in O(refs) time. Must run before the
// manager starts.
func registerExporterConfigIndexers(ctx context.Context, mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(ctx, &podtracev1alpha1.PodTrace{},
		IndexFieldPodTraceExporterRef,
		func(o client.Object) []string {
			pt, ok := o.(*podtracev1alpha1.PodTrace)
			if !ok || pt.Spec.ExporterRef.Name == "" {
				return nil
			}
			return []string{pt.Spec.ExporterRef.Name}
		},
	); err != nil {
		return fmt.Errorf("index PodTrace.spec.exporterRef.name: %w", err)
	}
	if err := mgr.GetFieldIndexer().IndexField(ctx, &podtracev1alpha1.PodTraceSession{},
		IndexFieldPodTraceSessionExporterRef,
		func(o client.Object) []string {
			pts, ok := o.(*podtracev1alpha1.PodTraceSession)
			if !ok || pts.Spec.ExporterRef.Name == "" {
				return nil
			}
			return []string{pts.Spec.ExporterRef.Name}
		},
	); err != nil {
		return fmt.Errorf("index PodTraceSession.spec.exporterRef.name: %w", err)
	}
	return nil
}

// setCondition wraps meta.SetStatusCondition with the project's
// shared invariant: every condition we write carries the current
// ObservedGeneration. apimachinery already manages
// LastTransitionTime (only updated when Status changes) and dedupes
// identical entries.
func setCondition(conds *[]metav1.Condition, generation int64, c metav1.Condition) {
	c.ObservedGeneration = generation
	meta.SetStatusCondition(conds, c)
}

func clampMessage(s string) string {
	if len(s) <= ecMaxConditionMessageLen {
		return s
	}
	return s[:ecMaxConditionMessageLen-3] + "..."
}

// statusEqual returns true when two ExporterConfigStatus values are
// indistinguishable from the API server's perspective. Used to skip
// no-op Patch calls in the reconcile loop.
func statusEqual(a, b podtracev1alpha1.ExporterConfigStatus) bool {
	if a.Ready != b.Ready ||
		a.ReferencedBy != b.ReferencedBy ||
		a.ObservedGeneration != b.ObservedGeneration {
		return false
	}
	return conditionsEqual(a.Conditions, b.Conditions)
}

func conditionsEqual(a, b []metav1.Condition) bool {
	if len(a) != len(b) {
		return false
	}
	bm := make(map[string]metav1.Condition, len(b))
	for _, c := range b {
		bm[c.Type] = c
	}
	for _, c := range a {
		other, ok := bm[c.Type]
		if !ok {
			return false
		}
		if c.Status != other.Status || c.Reason != other.Reason || c.Message != other.Message {
			return false
		}
	}
	return true
}
