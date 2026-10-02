//go:build envtest
// +build envtest

package operator

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestEverySessionAScheduleStartsGetsTheTemplatesReport(t *testing.T) {
	scheme, c, ns := setupSharedEnvtest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ensureExporterConfig(t, c, ns, "sch-otlp")
	sch := makeSchedule(t, c, ns, "report-runs", func(s *podtracev1alpha1.PodTraceSchedule) {
		s.Spec.SessionTemplate.Spec.ReportRef = &podtracev1alpha1.ReportReference{
			ConfigMap: &corev1.LocalObjectReference{Name: "report-runs-latest"},
		}
	})

	run := func(name string) *podtracev1alpha1.PodTraceSession {
		s := &podtracev1alpha1.PodTraceSession{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec:       *sch.Spec.SessionTemplate.Spec.DeepCopy(),
		}
		if err := controllerutil.SetControllerReference(sch, s, scheme); err != nil {
			t.Fatalf("owner reference: %v", err)
		}
		if err := c.Create(ctx, s); err != nil {
			t.Fatalf("create session %s: %v", name, err)
		}
		return s
	}

	for _, name := range []string{"report-runs-1", "report-runs-2", "report-runs-3"} {
		s := run(name)
		if err := ensureSessionReportObject(ctx, c, s); err != nil {
			t.Fatalf("%s was refused the schedule's report object: %v", name, err)
		}
		var cm corev1.ConfigMap
		if err := c.Get(ctx, types.NamespacedName{Name: "report-runs-latest", Namespace: ns}, &cm); err != nil {
			t.Fatalf("get report: %v", err)
		}
		if cm.Labels[LabelSessionName] != name || cm.Labels[LabelSchedule] != sch.Name {
			t.Errorf("after %s the report object is labelled %+v", name, cm.Labels)
		}
	}

	if err := c.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "app-settings", Namespace: ns}}); err != nil {
		t.Fatalf("create foreign ConfigMap: %v", err)
	}
	foreign := run("report-runs-foreign")
	foreign.Spec.ReportRef = &podtracev1alpha1.ReportReference{ConfigMap: &corev1.LocalObjectReference{Name: "app-settings"}}
	var conflict *reportObjectConflictError
	if err := ensureSessionReportObject(ctx, c, foreign); !errors.As(err, &conflict) {
		t.Errorf("a schedule run took over a ConfigMap no session created: %v", err)
	}
}
