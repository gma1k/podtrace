package operator

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// PodTraceReconciler is a thin orchestrator for continuous PodTrace CRs:
//
//   - Verifies the referenced ExporterConfig exists and is ready.
//   - Maintains an "exporter bundle" in the system namespace: a
//     ConfigMap with endpoint/config data plus a paired Secret carrying
//     resolved credential material. Agents read the bundle instead of
//     walking back to the user-namespace Secret, which keeps agent RBAC
//     scoped to systemNS for Secrets.
//   - Aggregates status.conditions from the per-node status entries
//     written directly by agents. It does NOT touch status.nodeStatus —
//     that array is agent-owned and patched via merge.
//
// The agent is not in the hot path: status rollup runs on the standard
// reconcile cadence, not per-event.
type PodTraceReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	SystemNamespace string
}

// +kubebuilder:rbac:groups=podtrace.io,resources=podtraces,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=podtrace.io,resources=podtraces/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=podtrace.io,resources=podtraces/finalizers,verbs=update
// +kubebuilder:rbac:groups=podtrace.io,resources=exporterconfigs,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=secrets;configmaps,verbs=get;list;watch;create;update;patch;delete

func (r *PodTraceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("podtrace", req.String())

	var pt podtracev1alpha1.PodTrace
	if err := r.Get(ctx, req.NamespacedName, &pt); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get PodTrace: %w", err)
	}

	// Deletion path: tear down cross-namespace children first, then
	// release the finalizer so the apiserver actually removes the CR.
	if !pt.DeletionTimestamp.IsZero() {
		if err := cleanupPodTraceChildren(ctx, r.Client, &pt, r.SystemNamespace); err != nil {
			return ctrl.Result{}, err
		}
		if removeFinalizer(&pt) {
			if err := r.Update(ctx, &pt); err != nil {
				return ctrl.Result{}, fmt.Errorf("clear finalizer: %w", err)
			}
		}
		return ctrl.Result{}, nil
	}
	if ensureFinalizer(&pt) {
		if err := r.Update(ctx, &pt); err != nil {
			return ctrl.Result{}, fmt.Errorf("set finalizer: %w", err)
		}
		// Re-queue; the Update mutated the object and we want a fresh
		// Get before running the rest of the reconcile.
		return ctrl.Result{Requeue: true}, nil
	}

	if pt.Spec.Paused {
		r.setCondition(&pt, ConditionPaused, metav1.ConditionTrue, "Paused", "spec.paused=true")
		r.setCondition(&pt, ConditionReady, metav1.ConditionFalse, "Paused", "tracing is paused")
		return ctrl.Result{}, r.Status().Update(ctx, &pt)
	}
	r.setCondition(&pt, ConditionPaused, metav1.ConditionFalse, "NotPaused", "")

	// Resolve the exporter. Its readiness gates bundle sync.
	var ec podtracev1alpha1.ExporterConfig
	ecKey := types.NamespacedName{Namespace: pt.Namespace, Name: pt.Spec.ExporterRef.Name}
	if err := r.Get(ctx, ecKey, &ec); err != nil {
		if apierrors.IsNotFound(err) {
			r.setCondition(&pt, ConditionDegraded, metav1.ConditionTrue, "ExporterNotFound",
				fmt.Sprintf("ExporterConfig %s not found", ecKey))
			r.setCondition(&pt, ConditionReady, metav1.ConditionFalse, "ExporterNotFound", "")
			_ = r.Status().Update(ctx, &pt)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get ExporterConfig: %w", err)
	}

	if err := r.syncExporterBundle(ctx, &pt, &ec); err != nil {
		logger.Error(err, "sync exporter bundle")
		r.setCondition(&pt, ConditionDegraded, metav1.ConditionTrue, "BundleSync", err.Error())
		_ = r.Status().Update(ctx, &pt)
		return ctrl.Result{}, err
	}
	r.setCondition(&pt, ConditionDegraded, metav1.ConditionFalse, "Reconciled", "")

	// matchedPods and ready-rollup are conservative when there are no
	// per-node reports yet (first reconcile). Agents patch status.nodeStatus
	// every ~30s (StatusReportInterval), after which this rollup is accurate.
	pt.Status.MatchedPods = countReadyPods(pt.Status.NodeStatus)
	allReady := len(pt.Status.NodeStatus) > 0 && allNodesReady(pt.Status.NodeStatus)
	r.setCondition(&pt, ConditionReady, conditionStatusFromBool(allReady), "AgentsReady",
		fmt.Sprintf("%d node(s) reporting", len(pt.Status.NodeStatus)))
	r.setCondition(&pt, ConditionReconciled, metav1.ConditionTrue, "Reconciled", "exporter bundle up to date")
	pt.Status.ObservedGeneration = pt.Generation

	if err := r.Status().Update(ctx, &pt); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, fmt.Errorf("update status: %w", err)
	}
	return ctrl.Result{}, nil
}

func (r *PodTraceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("podtrace").
		For(&podtracev1alpha1.PodTrace{}).
		Watches(
			&podtracev1alpha1.ExporterConfig{},
			handler.EnqueueRequestsFromMapFunc(r.exporterConfigToPodTraces),
		).
		WithOptions(defaultControllerOptions()).
		Complete(r)
}

func (r *PodTraceReconciler) exporterConfigToPodTraces(ctx context.Context, obj client.Object) []reconcile.Request {
	ec, ok := obj.(*podtracev1alpha1.ExporterConfig)
	if !ok {
		return nil
	}
	var list podtracev1alpha1.PodTraceList
	if err := r.List(ctx, &list, client.InNamespace(ec.Namespace)); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for i := range list.Items {
		pt := &list.Items[i]
		if pt.Spec.ExporterRef.Name == ec.Name {
			reqs = append(reqs, reconcile.Request{
				NamespacedName: client.ObjectKey{Namespace: pt.Namespace, Name: pt.Name},
			})
		}
	}
	return reqs
}

// syncExporterBundle creates / updates the per-PodTrace ConfigMap+Secret
// in the system namespace. The ConfigMap carries endpoint metadata that
// agents use to construct the exporter; the Secret carries the resolved
// credential material (copied from user-namespace Secrets at sync time).
//
// One bundle per PodTrace simplifies the agent-side view: an agent looks
// up "the bundle for PodTrace X" and that is the ground truth for
// everything needed to export its events.
func (r *PodTraceReconciler) syncExporterBundle(ctx context.Context, pt *podtracev1alpha1.PodTrace, ec *podtracev1alpha1.ExporterConfig) error {
	systemNS := r.SystemNamespace
	name := ExporterBundleName(pt.UID)

	payload, credSecretRef, err := renderBundlePayload(ec)
	if err != nil {
		return err
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: ManagedObjectMeta(name, systemNS, ComponentBundle, map[string]string{
			LabelPodTraceName:   pt.Name,
			LabelPodTraceNS:     pt.Namespace,
			LabelExporterConfig: ec.Name,
		}),
	}
	// No ownerReference: Kubernetes forbids a namespaced owner (PodTrace)
	// from owning a child in a different namespace. Finalizer + label-
	// based cleanup handles deletion — see finalizer.go.
	if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, cm, func() error {
		cm.Labels = mergeLabels(cm.Labels, map[string]string{
			LabelManagedBy:      ManagedByValue,
			LabelComponent:      ComponentBundle,
			LabelPodTraceName:   pt.Name,
			LabelPodTraceNS:     pt.Namespace,
			LabelExporterConfig: ec.Name,
		})
		cm.Annotations = mergeLabels(cm.Annotations, map[string]string{
			BundleAnnotationSourceRef: ec.Namespace + "/" + ec.Name,
		})
		cm.Data = payload
		return nil
	}); err != nil {
		return fmt.Errorf("bundle ConfigMap: %w", err)
	}

	// Only create a companion Secret when the exporter actually references
	// one. Exporters without credentials (e.g. plain Jaeger/Zipkin) get a
	// ConfigMap-only bundle.
	if credSecretRef != nil {
		credData, err := r.loadCredentialSecret(ctx, ec.Namespace, *credSecretRef)
		if err != nil {
			return fmt.Errorf("load credential Secret: %w", err)
		}
		secret := &corev1.Secret{
			ObjectMeta: ManagedObjectMeta(name, systemNS, ComponentBundle, map[string]string{
				LabelPodTraceName:   pt.Name,
				LabelPodTraceNS:     pt.Namespace,
				LabelExporterConfig: ec.Name,
			}),
		}
		if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
			secret.Labels = mergeLabels(secret.Labels, map[string]string{
				LabelManagedBy:      ManagedByValue,
				LabelComponent:      ComponentBundle,
				LabelPodTraceName:   pt.Name,
				LabelPodTraceNS:     pt.Namespace,
				LabelExporterConfig: ec.Name,
			})
			secret.Annotations = mergeLabels(secret.Annotations, map[string]string{
				BundleAnnotationSourceRef: ec.Namespace + "/" + ec.Name,
			})
			secret.Type = corev1.SecretTypeOpaque
			secret.Data = credData
			return nil
		}); err != nil {
			return fmt.Errorf("bundle Secret: %w", err)
		}
	}
	return nil
}

// loadCredentialSecret reads a SecretKeySelector from the ExporterConfig's
// namespace and returns just the one key the exporter referenced, keyed
// under a deterministic name (always "credential") so agents never have
// to re-parse the SecretKeySelector.
func (r *PodTraceReconciler) loadCredentialSecret(ctx context.Context, namespace string, ref podtracev1alpha1.SecretKeySelector) (map[string][]byte, error) {
	var src corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: ref.Name}, &src); err != nil {
		return nil, fmt.Errorf("get Secret %s/%s: %w", namespace, ref.Name, err)
	}
	val, ok := src.Data[ref.Key]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s has no key %q", namespace, ref.Name, ref.Key)
	}
	return map[string][]byte{"credential": val}, nil
}

// setCondition, scoped to PodTrace status.
func (r *PodTraceReconciler) setCondition(pt *podtracev1alpha1.PodTrace, condType string, status metav1.ConditionStatus, reason, message string) {
	pt.Status.Conditions = upsertCondition(pt.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
		ObservedGeneration: pt.Generation,
	})
}

func allNodesReady(ns []podtracev1alpha1.PodTraceNodeStatus) bool {
	for _, n := range ns {
		if !n.Ready {
			return false
		}
	}
	return true
}

// countReadyPods sums activeCgroups across all per-node reports as a
// proxy for matchedPods. cgroups and pods are 1:1 under the current
// target-resolution rules.
func countReadyPods(ns []podtracev1alpha1.PodTraceNodeStatus) int32 {
	total := int32(0)
	for _, n := range ns {
		total += n.ActiveCgroups
	}
	return total
}
