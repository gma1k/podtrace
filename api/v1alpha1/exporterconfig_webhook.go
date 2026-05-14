package v1alpha1

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// +kubebuilder:webhook:path=/validate-podtrace-io-v1alpha1-exporterconfig,mutating=false,failurePolicy=fail,sideEffects=None,groups=podtrace.io,resources=exporterconfigs,verbs=create;update,versions=v1alpha1,name=vexporterconfig.podtrace.io,admissionReviewVersions=v1

// ExporterConfigCustomValidator enforces that spec.type matches exactly
// one populated typed field. This is a cross-field consistency check that
// CRD-level markers (enums + optional sub-objects) cannot express:
// without it, a user could write `type: otlp` while populating `jaeger:`
// and the resource would be accepted but the agent would silently ignore it.
//
// The webhook does not need an API client — validation is pure-spec.
type ExporterConfigCustomValidator struct{}

func SetupExporterConfigWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(&ExporterConfig{}).
		WithValidator(&ExporterConfigCustomValidator{}).
		Complete()
}

var _ webhook.CustomValidator = &ExporterConfigCustomValidator{}

func (v *ExporterConfigCustomValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	ec, ok := obj.(*ExporterConfig)
	if !ok {
		return nil, fmt.Errorf("expected *ExporterConfig, got %T", obj)
	}
	return nil, ValidateExporterConfigVariant(ec.Spec)
}

func (v *ExporterConfigCustomValidator) ValidateUpdate(_ context.Context, _, newObj runtime.Object) (admission.Warnings, error) {
	ec, ok := newObj.(*ExporterConfig)
	if !ok {
		return nil, fmt.Errorf("expected *ExporterConfig, got %T", newObj)
	}
	return nil, ValidateExporterConfigVariant(ec.Spec)
}

func (v *ExporterConfigCustomValidator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}
