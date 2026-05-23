package v1alpha1

import (
	"context"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
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
	return ctrl.NewWebhookManagedBy(mgr, &podtracev1alpha1.ExporterConfig{}).
		WithValidator(&ExporterConfigCustomValidator{}).
		Complete()
}

var _ admission.Validator[*podtracev1alpha1.ExporterConfig] = &ExporterConfigCustomValidator{}

func (v *ExporterConfigCustomValidator) ValidateCreate(_ context.Context, ec *podtracev1alpha1.ExporterConfig) (admission.Warnings, error) {
	return nil, podtracev1alpha1.ValidateExporterConfigVariant(ec.Spec)
}

func (v *ExporterConfigCustomValidator) ValidateUpdate(_ context.Context, _, newEC *podtracev1alpha1.ExporterConfig) (admission.Warnings, error) {
	return nil, podtracev1alpha1.ValidateExporterConfigVariant(newEC.Spec)
}

func (v *ExporterConfigCustomValidator) ValidateDelete(_ context.Context, _ *podtracev1alpha1.ExporterConfig) (admission.Warnings, error) {
	return nil, nil
}
