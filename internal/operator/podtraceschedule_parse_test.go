package operator

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func scheduleWith(schedule string, tz *string) *podtracev1alpha1.PodTraceSchedule {
	return &podtracev1alpha1.PodTraceSchedule{
		ObjectMeta: metav1.ObjectMeta{Name: "nightly", Namespace: "default"},
		Spec: podtracev1alpha1.PodTraceScheduleSpec{
			Schedule: schedule,
			TimeZone: tz,
		},
	}
}

func TestParseSchedule_DefaultLocation(t *testing.T) {
	r := &PodTraceScheduleReconciler{}
	parsed, loc, err := r.parseSchedule(scheduleWith("*/5 * * * *", nil))
	if err != nil {
		t.Fatalf("parseSchedule: %v", err)
	}
	if parsed == nil {
		t.Fatal("expected a parsed schedule")
	}
	if loc == nil {
		t.Fatal("expected a non-nil location")
	}
}

func TestParseSchedule_NamedTimeZone(t *testing.T) {
	tz := "Europe/Amsterdam"
	r := &PodTraceScheduleReconciler{}
	_, loc, err := r.parseSchedule(scheduleWith("0 3 * * *", &tz))
	if err != nil {
		t.Fatalf("parseSchedule: %v", err)
	}
	if loc == nil || loc.String() != tz {
		t.Errorf("location = %v, want %s", loc, tz)
	}
}

func TestParseSchedule_InvalidTimeZone(t *testing.T) {
	tz := "Mars/Phobos"
	r := &PodTraceScheduleReconciler{}
	if _, _, err := r.parseSchedule(scheduleWith("0 3 * * *", &tz)); err == nil {
		t.Fatal("expected error for an unknown timezone")
	}
}

func TestParseSchedule_InvalidCronExpression(t *testing.T) {
	r := &PodTraceScheduleReconciler{}
	if _, _, err := r.parseSchedule(scheduleWith("not-a-cron", nil)); err == nil {
		t.Fatal("expected error for a malformed cron expression")
	}
}
