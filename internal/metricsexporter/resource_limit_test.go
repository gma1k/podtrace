package metricsexporter

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/gma1k/podtrace/internal/events"
)

func TestExportResourceLimitMetric_NilEventIgnored(t *testing.T) {
	ExportResourceLimitMetricWithContext(nil, "ns")
}

func TestExportResourceLimitMetric_UnknownResourceType(t *testing.T) {
	ExportResourceLimitMetricWithContext(&events.Event{TCPState: 99, Error: 85, Bytes: 100}, "unknown-type-ns")
	if got := testutil.ToFloat64(resourceUtilizationPercentGauge.WithLabelValues("unknown", "unknown-type-ns")); got != 85 {
		t.Fatalf("unknown resource type utilization = %v, want 85 (exported under the 'unknown' label)", got)
	}
}
