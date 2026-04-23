package v1alpha1

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// +kubebuilder:webhook:path=/validate-podtrace-io-v1alpha1-podtrace,mutating=false,failurePolicy=fail,sideEffects=None,groups=podtrace.io,resources=podtraces,verbs=create;update,versions=v1alpha1,name=vpodtrace.podtrace.io,admissionReviewVersions=v1

// PodTraceCustomValidator enforces cross-object invariants on PodTrace
// resources that cannot be expressed via CRD schema markers alone:
//
//   - Exactly one of spec.selector or spec.podRefs is set. Neither-or-both
//     is silently ambiguous — no pods targeted, or two sources of truth —
//     so we reject at admission instead of leaving the ambiguity to agent
//     runtime heuristics.
//   - spec.exporterRef.name refers to an existing ExporterConfig in the
//     same namespace. This requires an API read and therefore only fits
//     a webhook (CRD CEL rules cannot cross-object).
//
// PodTraceSpec does not declare a Duration field, so the apiserver
// rejects unknown fields via the CRD schema before this webhook fires.
type PodTraceCustomValidator struct {
	Client client.Client
}

// SetupPodTraceWebhookWithManager registers the validator onto mgr.
func SetupPodTraceWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(&PodTrace{}).
		WithValidator(&PodTraceCustomValidator{Client: mgr.GetClient()}).
		Complete()
}

var _ webhook.CustomValidator = &PodTraceCustomValidator{}

func (v *PodTraceCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	pt, ok := obj.(*PodTrace)
	if !ok {
		return nil, fmt.Errorf("expected *PodTrace, got %T", obj)
	}
	return v.validate(ctx, pt)
}

func (v *PodTraceCustomValidator) ValidateUpdate(ctx context.Context, _, newObj runtime.Object) (admission.Warnings, error) {
	pt, ok := newObj.(*PodTrace)
	if !ok {
		return nil, fmt.Errorf("expected *PodTrace, got %T", newObj)
	}
	return v.validate(ctx, pt)
}

func (v *PodTraceCustomValidator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

func (v *PodTraceCustomValidator) validate(ctx context.Context, pt *PodTrace) (admission.Warnings, error) {
	if err := validateSelectorExclusivity(pt.Spec.Selector, pt.Spec.PodRefs); err != nil {
		return nil, err
	}
	if err := resolveExporterRef(ctx, v.Client, pt.Namespace, pt.Spec.ExporterRef.Name); err != nil {
		return nil, err
	}
	return nil, nil
}
