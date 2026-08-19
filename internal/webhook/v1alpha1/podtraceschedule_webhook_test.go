package v1alpha1_test

import (
	"context"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	webhookv1alpha1 "github.com/gma1k/podtrace/internal/webhook/v1alpha1"
)

func validScheduleSpec(exporter string) podtracev1alpha1.PodTraceScheduleSpec {
	return podtracev1alpha1.PodTraceScheduleSpec{
		Schedule:          "*/5 * * * *",
		ConcurrencyPolicy: podtracev1alpha1.AllowConcurrent,
		SessionTemplate: podtracev1alpha1.PodTraceSessionTemplateSpec{
			Spec: podtracev1alpha1.PodTraceSessionSpec{
				Selector:    validSelector(),
				Duration:    metav1.Duration{Duration: 30 * time.Second},
				ExporterRef: podtracev1alpha1.LocalObjectReference{Name: exporter},
			},
		},
	}
}

func validTriggerSpec() *podtracev1alpha1.TriggerSpec {
	return &podtracev1alpha1.TriggerSpec{
		Sources: []podtracev1alpha1.TriggerSource{
			{Kind: podtracev1alpha1.TriggerSourceResourceAlert, MinSeverity: "critical"},
		},
	}
}

func malformedSelector() *metav1.LabelSelector {
	return &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "app", Operator: "Bogus", Values: []string{"x"}},
		},
	}
}

func TestPodTraceScheduleValidator(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(*podtracev1alpha1.PodTraceSchedule)
		exporter  string
		wantError string
	}{
		{
			name:      "happy-path",
			exporter:  "prod-otlp",
			wantError: "",
		},
		{
			name: "happy-path-six-field-cron",
			mutate: func(s *podtracev1alpha1.PodTraceSchedule) {
				s.Spec.Schedule = "0 */5 * * * *"
			},
			exporter: "prod-otlp",
		},
		{
			name: "happy-path-descriptor",
			mutate: func(s *podtracev1alpha1.PodTraceSchedule) {
				s.Spec.Schedule = "@hourly"
			},
			exporter: "prod-otlp",
		},
		{
			name: "invalid-cron",
			mutate: func(s *podtracev1alpha1.PodTraceSchedule) {
				s.Spec.Schedule = "not-a-cron"
			},
			exporter:  "prod-otlp",
			wantError: "spec.schedule",
		},
		{
			name: "invalid-timezone",
			mutate: func(s *podtracev1alpha1.PodTraceSchedule) {
				tz := "Not/A/Zone"
				s.Spec.TimeZone = &tz
			},
			exporter:  "prod-otlp",
			wantError: "spec.timeZone",
		},
		{
			name: "invalid-concurrency-policy",
			mutate: func(s *podtracev1alpha1.PodTraceSchedule) {
				s.Spec.ConcurrencyPolicy = "Bogus"
			},
			exporter:  "prod-otlp",
			wantError: "spec.concurrencyPolicy",
		},
		{
			name: "template-missing-exporter",
			mutate: func(s *podtracev1alpha1.PodTraceSchedule) {
				s.Spec.SessionTemplate.Spec.ExporterRef.Name = "does-not-exist"
			},
			exporter:  "prod-otlp",
			wantError: "ExporterConfig not found",
		},
		{
			name: "template-zero-duration",
			mutate: func(s *podtracev1alpha1.PodTraceSchedule) {
				s.Spec.SessionTemplate.Spec.Duration = metav1.Duration{Duration: 0}
			},
			exporter:  "prod-otlp",
			wantError: "duration",
		},
		{
			name: "template-selector-and-podrefs",
			mutate: func(s *podtracev1alpha1.PodTraceSchedule) {
				s.Spec.SessionTemplate.Spec.PodRefs = []podtracev1alpha1.PodRef{{Name: "foo"}}
			},
			exporter:  "prod-otlp",
			wantError: "mutually exclusive",
		},
		{
			name: "happy-path-trigger-mode",
			mutate: func(s *podtracev1alpha1.PodTraceSchedule) {
				s.Spec.Schedule = ""
				s.Spec.Trigger = validTriggerSpec()
			},
			exporter: "prod-otlp",
		},
		{
			name: "happy-path-trigger-every-source-kind",
			mutate: func(s *podtracev1alpha1.PodTraceSchedule) {
				s.Spec.Schedule = ""
				s.Spec.Trigger = &podtracev1alpha1.TriggerSpec{
					Sources: []podtracev1alpha1.TriggerSource{
						{Kind: podtracev1alpha1.TriggerSourceResourceAlert, MinSeverity: "warning"},
						{Kind: podtracev1alpha1.TriggerSourceOOMKill},
						{Kind: podtracev1alpha1.TriggerSourceErrorRate, MinSeverity: "fatal"},
					},
					ConcurrencyPolicy: podtracev1alpha1.ForbidConcurrent,
				}
			},
			exporter: "prod-otlp",
		},
		{
			name: "schedule-and-trigger-both-set",
			mutate: func(s *podtracev1alpha1.PodTraceSchedule) {
				s.Spec.Trigger = validTriggerSpec()
			},
			exporter:  "prod-otlp",
			wantError: "set exactly one of schedule or trigger, not both",
		},
		{
			name: "neither-schedule-nor-trigger-set",
			mutate: func(s *podtracev1alpha1.PodTraceSchedule) {
				s.Spec.Schedule = ""
			},
			exporter:  "prod-otlp",
			wantError: "exactly one of schedule or trigger is required",
		},
		{
			name: "trigger-without-sources",
			mutate: func(s *podtracev1alpha1.PodTraceSchedule) {
				s.Spec.Schedule = ""
				s.Spec.Trigger = &podtracev1alpha1.TriggerSpec{}
			},
			exporter:  "prod-otlp",
			wantError: "spec.trigger.sources",
		},
		{
			name: "trigger-invalid-concurrency-policy",
			mutate: func(s *podtracev1alpha1.PodTraceSchedule) {
				s.Spec.Schedule = ""
				s.Spec.Trigger = validTriggerSpec()
				s.Spec.Trigger.ConcurrencyPolicy = "Bogus"
			},
			exporter:  "prod-otlp",
			wantError: "spec.trigger.concurrencyPolicy",
		},
		{
			name: "trigger-malformed-selector",
			mutate: func(s *podtracev1alpha1.PodTraceSchedule) {
				s.Spec.Schedule = ""
				s.Spec.Trigger = validTriggerSpec()
				s.Spec.Trigger.Selector = malformedSelector()
			},
			exporter:  "prod-otlp",
			wantError: "spec.trigger.selector",
		},
		{
			name: "trigger-malformed-namespace-selector",
			mutate: func(s *podtracev1alpha1.PodTraceSchedule) {
				s.Spec.Schedule = ""
				s.Spec.Trigger = validTriggerSpec()
				s.Spec.Trigger.NamespaceSelector = malformedSelector()
			},
			exporter:  "prod-otlp",
			wantError: "spec.trigger.namespaceSelector",
		},
		{
			name: "trigger-mode-still-validates-session-template",
			mutate: func(s *podtracev1alpha1.PodTraceSchedule) {
				s.Spec.Schedule = ""
				s.Spec.Trigger = validTriggerSpec()
				s.Spec.SessionTemplate.Spec.ExporterRef.Name = "does-not-exist"
			},
			exporter:  "prod-otlp",
			wantError: "ExporterConfig not found",
		},
		{
			name: "trigger-mode-ignores-cron-only-fields",
			mutate: func(s *podtracev1alpha1.PodTraceSchedule) {
				s.Spec.Schedule = ""
				s.Spec.Trigger = validTriggerSpec()
				tz := "Not/A/Zone"
				s.Spec.TimeZone = &tz
			},
			exporter: "prod-otlp",
		},
		{
			name: "template-invalid-label-value",
			mutate: func(s *podtracev1alpha1.PodTraceSchedule) {
				s.Spec.SessionTemplate.Metadata.Labels = map[string]string{"team": "not a valid value"}
			},
			exporter:  "prod-otlp",
			wantError: "labels",
		},
		{
			name: "template-invalid-annotation-key",
			mutate: func(s *podtracev1alpha1.PodTraceSchedule) {
				s.Spec.SessionTemplate.Metadata.Annotations = map[string]string{"bad key": "v"}
			},
			exporter:  "prod-otlp",
			wantError: "annotations",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newClientWithExporter(t, "default", tc.exporter)
			validator := &webhookv1alpha1.PodTraceScheduleCustomValidator{Client: c}
			sch := &podtracev1alpha1.PodTraceSchedule{
				ObjectMeta: metav1.ObjectMeta{Name: "sch", Namespace: "default"},
				Spec:       validScheduleSpec("prod-otlp"),
			}
			if tc.mutate != nil {
				tc.mutate(sch)
			}
			_, err := validator.ValidateCreate(context.Background(), sch)
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantError)
				return
			}
			if !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("error %q did not contain %q", err.Error(), tc.wantError)
			}
		})
	}
}
