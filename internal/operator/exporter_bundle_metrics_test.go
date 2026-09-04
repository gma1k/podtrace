package operator

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func renderOTLPMetrics(t *testing.T, metrics *podtracev1alpha1.OTLPMetrics) map[string]string {
	t.Helper()
	data, _, _, err := renderBundlePayload(nil, ec("otlp-metrics", podtracev1alpha1.ExporterConfigSpec{
		Type: podtracev1alpha1.ExporterTypeOTLP,
		OTLP: &podtracev1alpha1.OTLPExporter{
			Endpoint: "otel:4318",
			Metrics:  metrics,
		},
	}), nil)
	if err != nil {
		t.Fatalf("renderBundlePayload: %v", err)
	}
	return data
}

func TestEnabledMetricsReachTheBundle(t *testing.T) {
	data := renderOTLPMetrics(t, &podtracev1alpha1.OTLPMetrics{
		Enabled:  true,
		Interval: &metav1.Duration{Duration: 45 * time.Second},
	})

	if data["metrics"] != "true" {
		t.Errorf("metrics = %q, want true", data["metrics"])
	}
	if data["metrics_interval_seconds"] != "45" {
		t.Errorf("metrics_interval_seconds = %q, want 45", data["metrics_interval_seconds"])
	}
}

func TestMetricsKeysAbsentUntilAskedFor(t *testing.T) {
	for name, metrics := range map[string]*podtracev1alpha1.OTLPMetrics{
		"absent":   nil,
		"disabled": {Enabled: false},
		"interval-without-enabled": {
			Interval: &metav1.Duration{Duration: time.Minute},
		},
	} {
		data := renderOTLPMetrics(t, metrics)
		if _, present := data["metrics"]; present {
			t.Errorf("%s rendered the metrics key; the agent reads absence as off", name)
		}
		if _, present := data["metrics_interval_seconds"]; present {
			t.Errorf("%s rendered an interval for an export that is not happening", name)
		}
	}
}

func TestZeroIntervalLeavesTheAgentDefault(t *testing.T) {
	data := renderOTLPMetrics(t, &podtracev1alpha1.OTLPMetrics{
		Enabled:  true,
		Interval: &metav1.Duration{},
	})
	if data["metrics"] != "true" {
		t.Fatalf("metrics = %q, want true", data["metrics"])
	}
	if _, present := data["metrics_interval_seconds"]; present {
		t.Error("a zero interval rendered a key; the default belongs in one place, the agent")
	}
}

func TestSubSecondIntervalTruncatesRatherThanRenderingZero(t *testing.T) {
	data := renderOTLPMetrics(t, &podtracev1alpha1.OTLPMetrics{
		Enabled:  true,
		Interval: &metav1.Duration{Duration: 500 * time.Millisecond},
	})
	if got := data["metrics_interval_seconds"]; got != "0" {
		t.Errorf("metrics_interval_seconds = %q, want 0; the agent clamps a sub-floor request "+
			"up to its minimum, and a whole-second wire format cannot carry 500ms", got)
	}
}
