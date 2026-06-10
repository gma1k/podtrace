package operator

import (
	"context"
	"fmt"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// FinalizerCleanup is the single finalizer name used by the operator for
// cross-namespace cleanup of resources a namespaced CR cannot own via
// ownerReferences. Kubernetes forbids a namespaced owner in namespace A
// from owning any object in namespace B, so we fall back to:
//
//  1. Put the child in podtrace-system, with labels naming the owning CR.
//  2. Add this finalizer to the CR at first reconcile.
//  3. On CR deletion, list children by label and delete them before
//     clearing the finalizer.
//
// This is the standard pattern in Prometheus Operator, cert-manager, etc.
const FinalizerCleanup = "podtrace.io/cleanup"

// ensureFinalizer adds FinalizerCleanup to the object if it is not
// already present. Returns true when the finalizer was added and the
// caller should update the object.
func ensureFinalizer(obj client.Object) bool {
	return controllerutil.AddFinalizer(obj, FinalizerCleanup)
}

// removeFinalizer removes FinalizerCleanup from the object. Returns
// true when removal changed the object.
func removeFinalizer(obj client.Object) bool {
	return controllerutil.RemoveFinalizer(obj, FinalizerCleanup)
}

// cleanupPodTraceChildren deletes the bundle ConfigMap + Secret this
// PodTrace owns across namespaces. Called on CR deletion.
func cleanupPodTraceChildren(ctx context.Context, c client.Client, pt *podtracev1alpha1.PodTrace, systemNS string) error {
	bundleName := ExporterBundleName(pt.UID)
	// Delete ConfigMap + Secret with matching name. Ignore NotFound so
	// repeated cleanups are idempotent.
	for _, obj := range []client.Object{
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: bundleName, Namespace: systemNS}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: bundleName, Namespace: systemNS}},
	} {
		if err := c.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete %T %s/%s: %w", obj, systemNS, bundleName, err)
		}
	}
	return nil
}

// candidateSystemNamespaces returns the deduplicated set of namespaces a
// CR's children may live in: the currently effective system namespace plus
// the operator default (they differ when TracerConfig.spec.systemNamespace
// is set, and the effective one may have changed between create and delete).
func candidateSystemNamespaces(effective, fallback string) []string {
	if effective == "" || effective == fallback {
		return []string{fallback}
	}
	return []string{effective, fallback}
}

// cleanupPodTraceSessionChildren deletes all resources this PodTraceSession
// owns across namespaces:
//
//   - per-node Jobs in the system namespace
//   - exporter bundle ConfigMap + optional Secret in the system namespace
//   - per-session Role + RoleBinding in the user namespace
//
// Called on CR deletion via the shared FinalizerCleanup finalizer.
// Each delete is NotFound-idempotent so repeated cleanup passes do
// not error.
func cleanupPodTraceSessionChildren(ctx context.Context, c client.Client, s *podtracev1alpha1.PodTraceSession, systemNS string) error {
	var jobs batchv1.JobList
	if err := c.List(ctx, &jobs, client.InNamespace(systemNS), client.MatchingLabels{
		LabelManagedBy:   ManagedByValue,
		LabelComponent:   ComponentSession,
		LabelSessionName: s.Name,
		LabelSessionNS:   s.Namespace,
	}); err != nil {
		return fmt.Errorf("list session Jobs: %w", err)
	}
	policy := metav1.DeletePropagationBackground
	for i := range jobs.Items {
		j := &jobs.Items[i]
		if j.UID == types.UID("") {
			continue
		}
		if err := c.Delete(ctx, j, &client.DeleteOptions{PropagationPolicy: &policy}); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete Job %s/%s: %w", j.Namespace, j.Name, err)
		}
	}

	// Session-scoped exporter bundle lives in the system namespace.
	bundleName := SessionBundleName(s.UID)
	objstoreCredsName := SessionObjectStoreCredsName(s.UID)
	for _, obj := range []client.Object{
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: bundleName, Namespace: systemNS}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: bundleName, Namespace: systemNS}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: objstoreCredsName, Namespace: systemNS}},
	} {
		if err := c.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete session bundle %T: %w", obj, err)
		}
	}

	// Per-session Role + RoleBinding in the user namespace.
	if err := cleanupSessionReportRBAC(ctx, c, s); err != nil {
		return err
	}
	return nil
}
