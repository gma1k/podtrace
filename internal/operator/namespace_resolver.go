package operator

import (
	"context"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// ResolveNamespaceSelector returns the sorted list of namespace names a
// given LabelSelector matches against the cluster's current Namespace
// objects, restricted to namespaces the CR is authorized to target:
// its own namespace plus any namespace whose AllowTracingFromAnnotation
// grants sourceNamespace access.
func ResolveNamespaceSelector(
	ctx context.Context,
	c client.Reader,
	sel *metav1.LabelSelector,
	sourceNamespace string,
) (allowed []string, denied []string, err error) {
	if sel == nil {
		return nil, nil, nil
	}
	selector, err := metav1.LabelSelectorAsSelector(sel)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid NamespaceSelector: %w", err)
	}

	var nsList corev1.NamespaceList
	if err := c.List(ctx, &nsList); err != nil {
		return nil, nil, fmt.Errorf("list namespaces: %w", err)
	}

	allowed = []string{}
	denied = []string{}
	for i := range nsList.Items {
		ns := &nsList.Items[i]
		if ns.DeletionTimestamp != nil {
			continue
		}
		if !selector.Matches(labels.Set(ns.Labels)) {
			continue
		}
		if podtracev1alpha1.NamespaceAllowsTracingFrom(ns, sourceNamespace) {
			allowed = append(allowed, ns.Name)
		} else {
			denied = append(denied, ns.Name)
		}
	}
	sort.Strings(allowed)
	sort.Strings(denied)
	return allowed, denied, nil
}

// filterGrantedPodRefs splits podRefs into the refs the CR may target
// and the sorted set of namespaces that were denied.
func filterGrantedPodRefs(
	ctx context.Context,
	c client.Reader,
	sourceNamespace string,
	refs []podtracev1alpha1.PodRef,
) (allowed []podtracev1alpha1.PodRef, denied []string, err error) {
	verdicts := map[string]bool{}
	deniedSet := map[string]struct{}{}
	for _, ref := range refs {
		ns := ref.Namespace
		if ns == "" || ns == sourceNamespace {
			allowed = append(allowed, ref)
			continue
		}
		granted, seen := verdicts[ns]
		if !seen {
			var nsObj corev1.Namespace
			switch err := c.Get(ctx, types.NamespacedName{Name: ns}, &nsObj); {
			case apierrors.IsNotFound(err):
				granted = false
			case err != nil:
				return nil, nil, fmt.Errorf("get namespace %q for podRef grant check: %w", ns, err)
			default:
				granted = podtracev1alpha1.NamespaceAllowsTracingFrom(&nsObj, sourceNamespace)
			}
			verdicts[ns] = granted
		}
		if granted {
			allowed = append(allowed, ref)
		} else {
			deniedSet[ns] = struct{}{}
		}
	}
	for ns := range deniedSet {
		denied = append(denied, ns)
	}
	sort.Strings(denied)
	return allowed, denied, nil
}

// crossNamespaceDeniedMessage renders the operator-facing explanation
// for namespaces excluded by the tenancy grant check.
func crossNamespaceDeniedMessage(sourceNamespace string, denied []string) string {
	return fmt.Sprintf(
		"cross-namespace target(s) %v excluded: namespace does not grant tracing to %q; annotate the target namespace with %s=%q (or a list, or %q) to allow it",
		denied, sourceNamespace,
		podtracev1alpha1.AllowTracingFromAnnotation, sourceNamespace,
		podtracev1alpha1.AllowTracingFromWildcard,
	)
}
