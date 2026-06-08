package v1alpha1_test

import (
	"context"
	"testing"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
	webhookv1alpha1 "github.com/podtrace/podtrace/internal/webhook/v1alpha1"
)

func TestExporterConfigValidator_Update(t *testing.T) {
	v := &webhookv1alpha1.ExporterConfigCustomValidator{}
	ctx := context.Background()

	valid := podtracev1alpha1.ExporterConfigSpec{
		Type: podtracev1alpha1.ExporterTypeOTLP,
		OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "localhost:4317"},
	}

	t.Run("unchanged spec short-circuits", func(t *testing.T) {
		old := &podtracev1alpha1.ExporterConfig{Spec: valid}
		newEC := &podtracev1alpha1.ExporterConfig{Spec: valid}
		if _, err := v.ValidateUpdate(ctx, old, newEC); err != nil {
			t.Fatalf("unchanged spec should pass, got %v", err)
		}
	})

	t.Run("changed spec is revalidated and valid", func(t *testing.T) {
		old := &podtracev1alpha1.ExporterConfig{Spec: podtracev1alpha1.ExporterConfigSpec{Type: "stdout"}}
		newEC := &podtracev1alpha1.ExporterConfig{Spec: valid}
		if _, err := v.ValidateUpdate(ctx, old, newEC); err != nil {
			t.Fatalf("valid changed spec should pass, got %v", err)
		}
	})

	t.Run("changed spec that is invalid is rejected", func(t *testing.T) {
		old := &podtracev1alpha1.ExporterConfig{Spec: valid}
		newEC := &podtracev1alpha1.ExporterConfig{Spec: podtracev1alpha1.ExporterConfigSpec{Type: podtracev1alpha1.ExporterTypeOTLP}}
		if _, err := v.ValidateUpdate(ctx, old, newEC); err == nil {
			t.Fatal("invalid changed spec should be rejected")
		}
	})

	t.Run("nil old falls through to validation", func(t *testing.T) {
		newEC := &podtracev1alpha1.ExporterConfig{Spec: valid}
		if _, err := v.ValidateUpdate(ctx, nil, newEC); err != nil {
			t.Fatalf("nil old with valid spec should pass, got %v", err)
		}
	})

	t.Run("delete always allowed", func(t *testing.T) {
		if _, err := v.ValidateDelete(ctx, &podtracev1alpha1.ExporterConfig{Spec: valid}); err != nil {
			t.Fatalf("delete should always pass, got %v", err)
		}
	})
}

func TestScheduleValidator_UpdateAndDelete(t *testing.T) {
	v := &webhookv1alpha1.PodTraceScheduleCustomValidator{}
	ctx := context.Background()

	valid := podtracev1alpha1.PodTraceScheduleSpec{Schedule: "*/5 * * * *"}

	t.Run("unchanged spec short-circuits", func(t *testing.T) {
		old := &podtracev1alpha1.PodTraceSchedule{Spec: valid}
		newS := &podtracev1alpha1.PodTraceSchedule{Spec: valid}
		if _, err := v.ValidateUpdate(ctx, old, newS); err != nil {
			t.Fatalf("unchanged spec should pass, got %v", err)
		}
	})

	t.Run("changed spec with bad cron is rejected", func(t *testing.T) {
		old := &podtracev1alpha1.PodTraceSchedule{Spec: valid}
		newS := &podtracev1alpha1.PodTraceSchedule{Spec: podtracev1alpha1.PodTraceScheduleSpec{Schedule: "not a cron"}}
		if _, err := v.ValidateUpdate(ctx, old, newS); err == nil {
			t.Fatal("bad cron should be rejected on update")
		}
	})

	t.Run("delete always allowed", func(t *testing.T) {
		if _, err := v.ValidateDelete(ctx, &podtracev1alpha1.PodTraceSchedule{Spec: valid}); err != nil {
			t.Fatalf("delete should always pass, got %v", err)
		}
	})
}
