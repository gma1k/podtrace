package operator

import (
	"context"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ResolveNamespaceSelector returns the sorted list of namespace names a
// given LabelSelector matches against the cluster's current Namespace objects.
func ResolveNamespaceSelector(
	ctx context.Context,
	c client.Reader,
	sel *metav1.LabelSelector,
) ([]string, error) {
	if sel == nil {
		return nil, nil
	}
	selector, err := metav1.LabelSelectorAsSelector(sel)
	if err != nil {
		return nil, fmt.Errorf("invalid NamespaceSelector: %w", err)
	}

	var nsList corev1.NamespaceList
	if err := c.List(ctx, &nsList); err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}

	matches := make([]string, 0, len(nsList.Items))
	for i := range nsList.Items {
		ns := &nsList.Items[i]
		if ns.DeletionTimestamp != nil {
			continue
		}
		if selector.Matches(labels.Set(ns.Labels)) {
			matches = append(matches, ns.Name)
		}
	}
	sort.Strings(matches)
	if matches == nil {
		matches = []string{}
	}
	return matches, nil
}
