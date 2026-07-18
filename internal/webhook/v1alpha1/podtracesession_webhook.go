package v1alpha1

import (
	"context"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// +kubebuilder:webhook:path=/validate-podtrace-io-v1alpha1-podtracesession,mutating=false,failurePolicy=fail,sideEffects=None,groups=podtrace.io,resources=podtracesessions,verbs=create;update,versions=v1alpha1,name=vpodtracesession.podtrace.io,admissionReviewVersions=v1

// PodTraceSessionCustomValidator enforces cross-object invariants on
// PodTraceSession resources. The CRD schema already enforces that
// spec.duration is required and non-negative; the remaining invariants
// require webhook-level checks:
//
//   - Exactly one of spec.selector or spec.podRefs is set.
//   - spec.exporterRef.name refers to an existing ExporterConfig in the
//     same namespace.
//   - spec.duration is strictly positive (guards against `0s`, which the
//     CRD schema accepts as a valid metav1.Duration but produces an
//     instantly-expired session that spawns Jobs with activeDeadline 0).
type PodTraceSessionCustomValidator struct {
	Client client.Client
}

func SetupPodTraceSessionWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &podtracev1alpha1.PodTraceSession{}).
		WithValidator(&PodTraceSessionCustomValidator{Client: mgr.GetClient()}).
		Complete()
}

var _ admission.Validator[*podtracev1alpha1.PodTraceSession] = &PodTraceSessionCustomValidator{}

func (v *PodTraceSessionCustomValidator) ValidateCreate(ctx context.Context, s *podtracev1alpha1.PodTraceSession) (admission.Warnings, error) {
	return v.validate(ctx, s)
}

func (v *PodTraceSessionCustomValidator) ValidateUpdate(ctx context.Context, oldSession, newSession *podtracev1alpha1.PodTraceSession) (admission.Warnings, error) {
	if oldSession != nil && specUnchanged(oldSession.Spec, newSession.Spec) {
		return nil, nil
	}
	return v.validate(ctx, newSession)
}

func (v *PodTraceSessionCustomValidator) ValidateDelete(_ context.Context, _ *podtracev1alpha1.PodTraceSession) (admission.Warnings, error) {
	return nil, nil
}

func (v *PodTraceSessionCustomValidator) validate(ctx context.Context, s *podtracev1alpha1.PodTraceSession) (admission.Warnings, error) {
	if err := validateSelectorExclusivity(s.Spec.Selector, s.Spec.PodRefs); err != nil {
		return nil, err
	}
	if err := validateNamespaceSelector(s.Spec.NamespaceSelector); err != nil {
		return nil, err
	}
	if s.Spec.Duration.Duration <= 0 {
		return nil, fmt.Errorf("spec.duration must be greater than zero")
	}
	if err := resolveExporterRef(ctx, v.Client, s.Namespace, s.Spec.ExporterRef.Name); err != nil {
		return nil, err
	}
	if err := validateReportRef(s.Spec.ReportRef); err != nil {
		return nil, err
	}
	return validateCrossNamespaceGrants(ctx, v.Client, s.Namespace, s.Spec.PodRefs, s.Spec.NamespaceSelector)
}

// validateReportRef enforces the sink-exclusivity rule and validates
// each sink shape. ObjectStore upload is wired as: URIs
// must be syntactically well-formed against the known schemes
// (s3, gs, azblob).
func validateReportRef(ref *podtracev1alpha1.ReportReference) error {
	if ref == nil {
		return nil
	}
	set := 0
	if ref.ConfigMap != nil {
		set++
	}
	if ref.Secret != nil {
		set++
	}
	if ref.ObjectStore != nil {
		set++
	}
	if set > 1 {
		return fmt.Errorf("spec.reportRef: at most one of configMap, secret, objectStore may be set")
	}
	if ref.ObjectStore != nil {
		if err := podtracev1alpha1.ValidateObjectStoreReference(ref.ObjectStore); err != nil {
			return err
		}
	}
	return nil
}
