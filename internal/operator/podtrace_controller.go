package operator

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
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
// +kubebuilder:rbac:groups=core,resources=namespaces,verbs=get;list;watch

func (r *PodTraceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var pt podtracev1alpha1.PodTrace
	if err := r.Get(ctx, req.NamespacedName, &pt); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get PodTrace: %w", err)
	}

	if !pt.DeletionTimestamp.IsZero() {
		for _, ns := range candidateSystemNamespaces(r.effectiveSystemNamespace(ctx), r.SystemNamespace) {
			if err := cleanupPodTraceChildren(ctx, r.Client, &pt, ns); err != nil {
				return ctrl.Result{}, err
			}
		}
		if removeFinalizer(&pt) {
			if err := r.Update(ctx, &pt); err != nil {
				if apierrors.IsConflict(err) {
					return ctrl.Result{RequeueAfter: time.Second}, nil
				}
				return ctrl.Result{}, fmt.Errorf("clear finalizer: %w", err)
			}
		}
		return ctrl.Result{}, nil
	}
	if ensureFinalizer(&pt) {
		if err := r.Update(ctx, &pt); err != nil {
			// Optimistic-concurrency conflict: the CR was modified between
			// our Get and Update. Requeue and try again on the fresh
			// version — this is normal, not an error.
			if apierrors.IsConflict(err) {
				return ctrl.Result{RequeueAfter: time.Second}, nil
			}
			return ctrl.Result{}, fmt.Errorf("set finalizer: %w", err)
		}
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}

	if pt.Spec.Paused {
		r.setCondition(&pt, ConditionPaused, metav1.ConditionTrue, "Paused", "spec.paused=true")
		r.setCondition(&pt, ConditionReady, metav1.ConditionFalse, "Paused", "tracing is paused")
		return ctrl.Result{}, r.Status().Update(ctx, &pt)
	}
	r.setCondition(&pt, ConditionPaused, metav1.ConditionFalse, "NotPaused", "")

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

	// Resolve spec.namespaceSelector against the cluster's Namespace
	// labels. Tri-state result:
	//   nil   → selector not set on the CR (agent falls back to own-ns)
	//   []{}  → selector set but matched zero namespaces
	//   list  → resolved allowlist
	targetNamespaces, err := ResolveNamespaceSelector(ctx, r.Client, pt.Spec.NamespaceSelector)
	if err != nil {
		r.setCondition(&pt, ConditionDegraded, metav1.ConditionTrue, "NamespaceSelectorInvalid", err.Error())
		_ = r.Status().Update(ctx, &pt)
		return ctrl.Result{}, nil
	}

	if err := r.syncExporterBundle(ctx, &pt, &ec, targetNamespaces); err != nil {
		r.setCondition(&pt, ConditionDegraded, metav1.ConditionTrue, "BundleSync", err.Error())
		r.setCondition(&pt, ConditionPolicyApplied, metav1.ConditionFalse, "BundleSync", err.Error())
		_ = r.Status().Update(ctx, &pt)
		return ctrl.Result{RequeueAfter: 60 * time.Second}, nil
	}

	pt.Status.TargetNamespaces = targetNamespaces
	pt.Status.Policy = resolvePolicyStatus(policyFromPodTrace(&pt), &ec)
	r.setCondition(&pt, ConditionPolicyApplied, metav1.ConditionTrue, "Reconciled", "policy resolved and written to bundle")

	if node, msg, reason, ok := firstDegradedNode(pt.Status.NodeStatus); ok {
		condReason := string(reason)
		if condReason == "" {
			condReason = "AgentNodeStatus"
		}
		r.setCondition(&pt, ConditionDegraded, metav1.ConditionTrue, condReason,
			fmt.Sprintf("node %s: %s", node, msg))
	} else {
		r.setCondition(&pt, ConditionDegraded, metav1.ConditionFalse, "Reconciled", "")
	}

	pt.Status.MatchedPods = countReadyPods(pt.Status.NodeStatus)
	allReady := len(pt.Status.NodeStatus) > 0 && allNodesReady(pt.Status.NodeStatus)
	r.setCondition(&pt, ConditionReady, conditionStatusFromBool(allReady), "AgentsReady",
		fmt.Sprintf("%d node(s) reporting", len(pt.Status.NodeStatus)))
	r.setCondition(&pt, ConditionReconciled, metav1.ConditionTrue, "Reconciled", "exporter bundle up to date")
	pt.Status.ObservedGeneration = pt.Generation

	if err := r.Status().Update(ctx, &pt); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{RequeueAfter: time.Second}, nil
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
		Watches(
			&corev1.Namespace{},
			handler.EnqueueRequestsFromMapFunc(r.namespaceToPodTraces),
		).
		// Bundle Secrets are copies of the referenced credential data, so a
		// rotation must re-trigger the PodTraces that snapshot it; the
		// ExporterConfig watch alone does not fire (the EC itself is
		// unchanged and its readiness status stays equal).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.secretToPodTraces),
		).
		WithOptions(defaultControllerOptions()).
		Complete(r)
}

// secretToPodTraces maps a Secret event to the PodTraces whose
// ExporterConfig references that Secret.
func (r *PodTraceReconciler) secretToPodTraces(ctx context.Context, obj client.Object) []reconcile.Request {
	var reqs []reconcile.Request
	for _, ec := range exporterConfigsReferencingSecret(ctx, r.Client, obj) {
		reqs = append(reqs, r.exporterConfigToPodTraces(ctx, &ec)...)
	}
	return reqs
}

// namespaceToPodTraces returns the set of PodTraces that should
// re-reconcile when any Namespace event fires.
func (r *PodTraceReconciler) namespaceToPodTraces(ctx context.Context, _ client.Object) []reconcile.Request {
	var list podtracev1alpha1.PodTraceList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	out := make([]reconcile.Request, 0, len(list.Items))
	for i := range list.Items {
		pt := &list.Items[i]
		if pt.Spec.NamespaceSelector == nil {
			continue
		}
		out = append(out, reconcile.Request{
			NamespacedName: client.ObjectKey{Namespace: pt.Namespace, Name: pt.Name},
		})
	}
	return out
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

func (r *PodTraceReconciler) syncExporterBundle(ctx context.Context, pt *podtracev1alpha1.PodTrace, ec *podtracev1alpha1.ExporterConfig, targetNamespaces []string) error {
	// The bundle must live where agents read it. Agents are launched with
	// --system-namespace set to the TracerConfig's systemNamespace override
	// (tracerconfig_daemonset.go), so writing to the operator default here
	// made continuous tracing silently export nothing whenever the override
	// was set: agents looked in a namespace the operator never wrote.
	systemNS := r.effectiveSystemNamespace(ctx)
	name := ExporterBundleName(pt.UID)

	payload, credSecretRef, headersFrom, err := renderBundlePayload(policyFromPodTrace(pt), ec, targetNamespaces)
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

	if credSecretRef != nil || headersFrom != nil {
		credData, err := buildBundleSecretData(ctx, r.Client, ec.Namespace, credSecretRef, headersFrom)
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

// effectiveSystemNamespace returns the namespace agents read bundles from:
// the default TracerConfig's spec.systemNamespace override when set,
// otherwise the operator default. Bundles must be written (and cleaned up)
// there, mirroring the --system-namespace the rendered DaemonSet passes to
// agents.
func (r *PodTraceReconciler) effectiveSystemNamespace(ctx context.Context) string {
	var tc podtracev1alpha1.TracerConfig
	if err := r.Get(ctx, types.NamespacedName{Name: "default"}, &tc); err == nil && tc.Spec.SystemNamespace != "" {
		return tc.Spec.SystemNamespace
	}
	return r.SystemNamespace
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

// firstDegradedNode returns the (node, message, reason) of the
// lexicographically first NodeStatus row that an agent has tombstoned
// (Ready=false with a non-empty Message).
func firstDegradedNode(ns []podtracev1alpha1.PodTraceNodeStatus) (node, message string, reason podtracev1alpha1.NodeStatusReason, ok bool) {
	for _, n := range ns {
		if n.Ready || n.Message == "" {
			continue
		}
		if !ok || n.Node < node {
			node = n.Node
			message = n.Message
			reason = n.Reason
			ok = true
		}
	}
	return node, message, reason, ok
}

// countReadyPods sums the per-node matched-pod counts.
func countReadyPods(ns []podtracev1alpha1.PodTraceNodeStatus) int32 {
	total := int32(0)
	for _, n := range ns {
		total += n.MatchedPods
	}
	return total
}
