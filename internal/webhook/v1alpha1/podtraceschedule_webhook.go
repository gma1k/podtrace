package v1alpha1

import (
	"context"
	"fmt"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// +kubebuilder:webhook:path=/validate-podtrace-io-v1alpha1-podtraceschedule,mutating=false,failurePolicy=fail,sideEffects=None,groups=podtrace.io,resources=podtraceschedules,verbs=create;update,versions=v1alpha1,name=vpodtraceschedule.podtrace.io,admissionReviewVersions=v1

// PodTraceScheduleCustomValidator enforces admission-time invariants on
// PodTraceSchedule resources: cron syntax, time zone validity, and
// (recursively) the embedded SessionTemplate spec, so a schedule cannot
// fire sessions that would themselves be rejected.
type PodTraceScheduleCustomValidator struct {
	Client client.Client
}

func SetupPodTraceScheduleWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &podtracev1alpha1.PodTraceSchedule{}).
		WithValidator(&PodTraceScheduleCustomValidator{Client: mgr.GetClient()}).
		Complete()
}

var _ admission.Validator[*podtracev1alpha1.PodTraceSchedule] = &PodTraceScheduleCustomValidator{}

func (v *PodTraceScheduleCustomValidator) ValidateCreate(ctx context.Context, s *podtracev1alpha1.PodTraceSchedule) (admission.Warnings, error) {
	return v.validate(ctx, s)
}

func (v *PodTraceScheduleCustomValidator) ValidateUpdate(ctx context.Context, _, newSchedule *podtracev1alpha1.PodTraceSchedule) (admission.Warnings, error) {
	return v.validate(ctx, newSchedule)
}

func (v *PodTraceScheduleCustomValidator) ValidateDelete(_ context.Context, _ *podtracev1alpha1.PodTraceSchedule) (admission.Warnings, error) {
	return nil, nil
}

func (v *PodTraceScheduleCustomValidator) validate(ctx context.Context, s *podtracev1alpha1.PodTraceSchedule) (admission.Warnings, error) {
	if _, err := podtracev1alpha1.ParseSchedule(s.Spec.Schedule); err != nil {
		return nil, fmt.Errorf("spec.schedule: %w", err)
	}
	if s.Spec.TimeZone != nil && *s.Spec.TimeZone != "" {
		if _, err := time.LoadLocation(*s.Spec.TimeZone); err != nil {
			return nil, fmt.Errorf("spec.timeZone: %w", err)
		}
	}
	switch s.Spec.ConcurrencyPolicy {
	case "", podtracev1alpha1.AllowConcurrent, podtracev1alpha1.ForbidConcurrent, podtracev1alpha1.ReplaceConcurrent:
	default:
		return nil, fmt.Errorf("spec.concurrencyPolicy: unknown policy %q", s.Spec.ConcurrencyPolicy)
	}

	tmpl := &s.Spec.SessionTemplate.Spec
	if err := validateSelectorExclusivity(tmpl.Selector, tmpl.PodRefs); err != nil {
		return nil, fmt.Errorf("spec.sessionTemplate.spec.%w", err)
	}
	if err := validateNamespaceSelector(tmpl.NamespaceSelector); err != nil {
		return nil, fmt.Errorf("spec.sessionTemplate.%w", err)
	}
	if tmpl.Duration.Duration <= 0 {
		return nil, fmt.Errorf("spec.sessionTemplate.spec.duration must be greater than zero")
	}
	if err := resolveExporterRef(ctx, v.Client, s.Namespace, tmpl.ExporterRef.Name); err != nil {
		return nil, fmt.Errorf("spec.sessionTemplate.%w", err)
	}
	if err := validateReportRef(tmpl.ReportRef); err != nil {
		return nil, fmt.Errorf("spec.sessionTemplate.%w", err)
	}
	return nil, nil
}
