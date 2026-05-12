package v1alpha1

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

func validateSelectorExclusivity(selector *metav1.LabelSelector, podRefs []PodRef) error {
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
// ExporterConfig that exists in the caller's namespace. Cross-namespace
// references are not supported: the referent and the referring trace
// must share a namespace so that Secret refs (which are namespace-scoped)
// remain unambiguous.
func resolveExporterRef(ctx context.Context, c client.Client, namespace, name string) error {
	if name == "" {
		return fmt.Errorf("spec.exporterRef.name is required")
	}
	if c == nil {
		// Defensive: if the webhook was wired without a client, fail
		// closed rather than silently skipping the referential check.
		return fmt.Errorf("webhook client not configured; cannot resolve ExporterConfig %q", name)
	}
	var ec ExporterConfig
	err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &ec)
	if err == nil {
		return nil
	}
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("spec.exporterRef.name %q: ExporterConfig not found in namespace %q", name, namespace)
	}
	return fmt.Errorf("spec.exporterRef.name %q: %w", name, err)
}

// validateExporterConfigVariant enforces that the typed field matching
// spec.type is populated, and only that one. This cannot be expressed as
// a simple CRD marker: it is a cross-field invariant.
func validateExporterConfigVariant(spec ExporterConfigSpec) error {
	present := map[ExporterType]bool{
		ExporterTypeOTLP:    spec.OTLP != nil,
		ExporterTypeJaeger:  spec.Jaeger != nil,
		ExporterTypeZipkin:  spec.Zipkin != nil,
		ExporterTypeSplunk:  spec.Splunk != nil,
		ExporterTypeDataDog: spec.DataDog != nil,
	}

	var populated []ExporterType
	for t, ok := range present {
		if ok {
			populated = append(populated, t)
		}
	}
	if len(populated) == 0 {
		return fmt.Errorf("spec.%s must be set when spec.type is %q", spec.Type, spec.Type)
	}
	if len(populated) > 1 {
		return fmt.Errorf("only one of spec.otlp/jaeger/zipkin/splunk/datadog may be set")
	}
	if populated[0] != spec.Type {
		return fmt.Errorf("spec.type %q does not match populated field spec.%s", spec.Type, populated[0])
	}
	return nil
}
