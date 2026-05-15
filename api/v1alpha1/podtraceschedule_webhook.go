package v1alpha1

import (
	"context"
	"fmt"
	"time"

	"github.com/robfig/cron/v3"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// +kubebuilder:webhook:path=/validate-podtrace-io-v1alpha1-podtraceschedule,mutating=false,failurePolicy=fail,sideEffects=None,groups=podtrace.io,resources=podtraceschedules,verbs=create;update,versions=v1alpha1,name=vpodtraceschedule.podtrace.io,admissionReviewVersions=v1

// scheduleParser accepts both 5-field (CronJob-style) and 6-field
// (leading seconds) expressions, plus descriptors like @hourly.
var scheduleParser = cron.NewParser(
	cron.SecondOptional |
		cron.Minute |
		cron.Hour |
		cron.Dom |
		cron.Month |
		cron.Dow |
		cron.Descriptor,
)

// ParseSchedule is exported so the controller can reuse the exact same
// parser configuration the webhook accepts.
func ParseSchedule(expr string) (cron.Schedule, error) {
	return scheduleParser.Parse(expr)
}

// PodTraceScheduleCustomValidator enforces admission-time invariants on
// PodTraceSchedule resources: cron syntax, time zone validity, and
// (recursively) the embedded SessionTemplate spec, so a schedule cannot
// fire sessions that would themselves be rejected.
type PodTraceScheduleCustomValidator struct {
	Client client.Client
}

func SetupPodTraceScheduleWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(&PodTraceSchedule{}).
		WithValidator(&PodTraceScheduleCustomValidator{Client: mgr.GetClient()}).
		Complete()
}

var _ webhook.CustomValidator = &PodTraceScheduleCustomValidator{}

func (v *PodTraceScheduleCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	s, ok := obj.(*PodTraceSchedule)
	if !ok {
		return nil, fmt.Errorf("expected *PodTraceSchedule, got %T", obj)
	}
	return v.validate(ctx, s)
}

func (v *PodTraceScheduleCustomValidator) ValidateUpdate(ctx context.Context, _, newObj runtime.Object) (admission.Warnings, error) {
	s, ok := newObj.(*PodTraceSchedule)
	if !ok {
		return nil, fmt.Errorf("expected *PodTraceSchedule, got %T", newObj)
	}
	return v.validate(ctx, s)
}

func (v *PodTraceScheduleCustomValidator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

func (v *PodTraceScheduleCustomValidator) validate(ctx context.Context, s *PodTraceSchedule) (admission.Warnings, error) {
	if _, err := scheduleParser.Parse(s.Spec.Schedule); err != nil {
		return nil, fmt.Errorf("spec.schedule: %w", err)
	}
	if s.Spec.TimeZone != nil && *s.Spec.TimeZone != "" {
		if _, err := time.LoadLocation(*s.Spec.TimeZone); err != nil {
			return nil, fmt.Errorf("spec.timeZone: %w", err)
		}
	}
	switch s.Spec.ConcurrencyPolicy {
	case "", AllowConcurrent, ForbidConcurrent, ReplaceConcurrent:
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