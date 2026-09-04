package v1alpha1

import (
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func otlpMetricsSpec(metrics *OTLPMetrics) ExporterConfigSpec {
	return ExporterConfigSpec{
		Type: ExporterTypeOTLP,
		OTLP: &OTLPExporter{Endpoint: "otel:4318", Metrics: metrics},
	}
}

func TestMetricsExportIsAcceptedOnAnOTLPExporter(t *testing.T) {
	for name, metrics := range map[string]*OTLPMetrics{
		"absent": nil,
		"off":    {},
		"on":     {Enabled: true},
		"timed":  {Enabled: true, Interval: &metav1.Duration{Duration: 30 * time.Second}},
		"zeroed": {Enabled: true, Interval: &metav1.Duration{}},
	} {
		if err := ValidateExporterConfigVariant(otlpMetricsSpec(metrics)); err != nil {
			t.Errorf("%s was rejected: %v", name, err)
		}
	}
}

func TestNegativeMetricsIntervalIsRejected(t *testing.T) {
	err := ValidateExporterConfigVariant(otlpMetricsSpec(&OTLPMetrics{
		Enabled:  true,
		Interval: &metav1.Duration{Duration: -30 * time.Second},
	}))
	if err == nil {
		t.Fatal("a negative interval was accepted; it would be silently ignored rather than " +
			"obeyed, which is a field that does nothing")
	}
	if !strings.Contains(err.Error(), "spec.otlp.metrics.interval") {
		t.Errorf("error %q does not name the offending field", err)
	}
}
