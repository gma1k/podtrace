// Package v1alpha1 holds the admission webhook validators for the
// podtrace.io/v1alpha1 API types. Validators live here instead of in
// api/v1alpha1/ so that the API package's only dependency is
// k8s.io/apimachinery, consumers vendoring just the API types do not
// pull in controller-runtime, and controller-gen's deepcopy generator
// has no non-API structs to choke on.
//
// Each API version has its own webhook package because apiserver serves
// all served versions concurrently and validation rules may differ
// across versions.
package v1alpha1

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func validateNamespaceSelector(sel *metav1.LabelSelector) error {
	if sel == nil {
		return nil
	}
	if _, err := metav1.LabelSelectorAsSelector(sel); err != nil {
		return fmt.Errorf("spec.namespaceSelector: %w", err)
	}
	return nil
}

func validateSelectorExclusivity(selector *metav1.LabelSelector, podRefs []podtracev1alpha1.PodRef) error {
	hasSelector := selector != nil && (len(selector.MatchLabels) > 0 || len(selector.MatchExpressions) > 0)
	hasPodRefs := len(podRefs) > 0
	switch {
	case !hasSelector && !hasPodRefs:
		return fmt.Errorf("one of spec.selector or spec.podRefs must be set")
	case hasSelector && hasPodRefs:
		return fmt.Errorf("spec.selector and spec.podRefs are mutually exclusive")
	}
	return nil
}

// resolveExporterRef verifies that spec.exporterRef.name refers to an
// ExporterConfig that exists in the caller's namespace.
func resolveExporterRef(ctx context.Context, c client.Client, namespace, name string) error {
	if name == "" {
		return fmt.Errorf("spec.exporterRef.name is required")
	}
	if c == nil {
		return fmt.Errorf("webhook client not configured; cannot resolve ExporterConfig %q", name)
	}
	var ec podtracev1alpha1.ExporterConfig
	err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &ec)
	if err == nil {
		return nil
	}
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("spec.exporterRef.name %q: ExporterConfig not found in namespace %q", name, namespace)
	}
	return fmt.Errorf("spec.exporterRef.name %q: %w", name, err)
}