package operator

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func sessionWithExporter(name string) *podtracev1alpha1.PodTraceSession {
	return &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "ns", UID: "uid-1"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			Duration:    metav1.Duration{Duration: 30_000_000_000},
			ExporterRef: corev1.LocalObjectReference{Name: name},
			ReportRef: &podtracev1alpha1.ReportReference{
				ConfigMap: &corev1.LocalObjectReference{Name: "report"},
			},
		},
	}
}

func sessionJobArgs(t *testing.T, s *podtracev1alpha1.PodTraceSession) []string {
	t.Helper()
	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       podtracev1alpha1.TracerConfigSpec{Image: "ghcr.io/gma1k/podtrace:test"},
	}
	spec := buildSessionJobSpec(s, tc, "node-1", sessionTargets{})
	for _, c := range spec.Template.Spec.Containers {
		if c.Name != reportUploaderContainerName {
			return c.Args
		}
	}
	t.Fatal("no main container in the session Job")
	return nil
}

func TestAReportOnlySessionDoesNotAskForAnExporterBundle(t *testing.T) {
	s := sessionWithExporter("")

	args := strings.Join(sessionJobArgs(t, s), " ")
	if strings.Contains(args, "--exporter-from-file") {
		t.Errorf("args = %q; a session with no exporterRef must not ask for a bundle. The "+
			"ConfigMap is never created for it and the volume is optional, so the Job would "+
			"fail reading a file that was never meant to exist", args)
	}
	if strings.Contains(args, "--tracing") {
		t.Errorf("args = %q; span export was enabled with nothing to export to", args)
	}
	if !strings.Contains(args, "--summary-file") {
		t.Errorf("args = %q; the report path must survive having no exporter", args)
	}
}

func TestASessionWithAnExporterStillGetsItsBundle(t *testing.T) {
	s := sessionWithExporter("otlp")

	args := strings.Join(sessionJobArgs(t, s), " ")
	for _, want := range []string{"--tracing", "--exporter-from-file"} {
		if !strings.Contains(args, want) {
			t.Errorf("args = %q, want %s", args, want)
		}
	}
}

func TestBundleRenderingIsSkippedWhenNoExporterIsReferenced(t *testing.T) {
	err := ensureSessionExporterBundleIfReferenced(
		t.Context(), nil, nil, sessionWithExporter(""), nil, "podtrace-system", false)
	if err != nil {
		t.Errorf("ensureSessionExporterBundleIfReferenced = %v, want nil. It must not touch the "+
			"client at all for a report-only session; a nil client here proves it did not", err)
	}
}
