package operator

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func scheduleRun(name, schedule string) *podtracev1alpha1.PodTraceSession {
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "team-a", UID: "uid-" + types.UID(name)},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			ReportRef: &podtracev1alpha1.ReportReference{ConfigMap: &corev1.LocalObjectReference{Name: "nightly-report"}},
		},
	}
	if schedule != "" {
		controller := true
		s.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: podtracev1alpha1.GroupVersion.String(),
			Kind:       "PodTraceSchedule",
			Name:       schedule,
			UID:        "uid-" + types.UID(schedule),
			Controller: &controller,
		}}
	}
	return s
}

func reportLabels(t *testing.T, c client.Client) map[string]string {
	t.Helper()
	var cm corev1.ConfigMap
	if err := c.Get(context.Background(), types.NamespacedName{Name: "nightly-report", Namespace: "team-a"}, &cm); err != nil {
		t.Fatalf("get report ConfigMap: %v", err)
	}
	return cm.Labels
}

func TestALaterRunOfTheSameScheduleTakesOverItsReport(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().WithScheme(newRBACScheme(t)).Build()

	first := scheduleRun("nightly-1", "nightly")
	if err := ensureSessionReportObject(ctx, c, first); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if got := reportLabels(t, c)[LabelSchedule]; got != "nightly" {
		t.Errorf("report object schedule label = %q, want nightly", got)
	}

	second := scheduleRun("nightly-2", "nightly")
	if err := ensureSessionReportObject(ctx, c, second); err != nil {
		t.Fatalf("second run of the same schedule was refused its report: %v", err)
	}
	if !reportObjectOwnedBySession(reportLabels(t, c), second) {
		t.Errorf("report object not handed to the second run: %+v", reportLabels(t, c))
	}
	if err := ensureSessionReportObject(ctx, c, second); err != nil {
		t.Fatalf("re-reconciling the second run: %v", err)
	}
}

func TestAnotherSchedulesReportIsStillRefused(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().WithScheme(newRBACScheme(t)).Build()
	if err := ensureSessionReportObject(ctx, c, scheduleRun("nightly-1", "nightly")); err != nil {
		t.Fatalf("first run: %v", err)
	}

	for name, s := range map[string]*podtracev1alpha1.PodTraceSession{
		"another schedule": scheduleRun("hourly-1", "hourly"),
		"no schedule":      scheduleRun("manual", ""),
		"label-only claimer": func() *podtracev1alpha1.PodTraceSession {
			s := scheduleRun("claimer", "")
			s.Labels = map[string]string{LabelSchedule: "nightly"}
			return s
		}(),
	} {
		var conflict *reportObjectConflictError
		if err := ensureSessionReportObject(ctx, c, s); !errors.As(err, &conflict) {
			t.Errorf("%s: want a report object conflict, got %v", name, err)
		}
	}
	if got := reportLabels(t, c)[LabelSessionName]; got != "nightly-1" {
		t.Errorf("a refused session relabelled the report object to %q", got)
	}
}

func TestAScheduleRunDoesNotTakeOverAnObjectThatIsNotAReport(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().WithScheme(newRBACScheme(t)).WithObjects(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "nightly-report", Namespace: "team-a", Labels: map[string]string{LabelSchedule: "nightly"}},
		Data:       map[string]string{"app.conf": "keep me"},
	}).Build()

	var conflict *reportObjectConflictError
	if err := ensureSessionReportObject(ctx, c, scheduleRun("nightly-2", "nightly")); !errors.As(err, &conflict) {
		t.Fatalf("a ConfigMap that is not a session report was taken over: %v", err)
	}
}

func TestAReportTakeoverThatCannotBeWrittenFails(t *testing.T) {
	ctx := context.Background()
	c := fake.NewClientBuilder().WithScheme(newRBACScheme(t)).WithInterceptorFuncs(interceptor.Funcs{
		Update: func(context.Context, client.WithWatch, client.Object, ...client.UpdateOption) error {
			return errors.New("apiserver unavailable")
		},
	}).Build()
	if err := ensureSessionReportObject(ctx, c, scheduleRun("nightly-1", "nightly")); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if err := ensureSessionReportObject(ctx, c, scheduleRun("nightly-2", "nightly")); err == nil {
		t.Fatal("a failed takeover was reported as success")
	}
}

func TestOnlyAPodTraceScheduleControllerCountsAsTheSchedule(t *testing.T) {
	s := scheduleRun("x", "nightly")
	if got := controllingSchedule(s); got != "nightly" {
		t.Errorf("controllingSchedule = %q, want nightly", got)
	}
	s.OwnerReferences[0].APIVersion = "example.com/v1"
	if got := controllingSchedule(s); got != "" {
		t.Errorf("a PodTraceSchedule kind from another group counted: %q", got)
	}
	s.OwnerReferences[0].APIVersion = "not/a/group/version"
	if got := controllingSchedule(s); got != "" {
		t.Errorf("an unparseable apiVersion counted: %q", got)
	}
	s.OwnerReferences[0].APIVersion = podtracev1alpha1.GroupVersion.String()
	s.OwnerReferences[0].Kind = "Deployment"
	if got := controllingSchedule(s); got != "" {
		t.Errorf("a Deployment controller counted as a schedule: %q", got)
	}
}
