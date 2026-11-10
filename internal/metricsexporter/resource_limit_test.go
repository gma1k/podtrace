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

func TestExportResourceLimitMetric_UsesTheLimitTheEventCarries(t *testing.T) {
	const limit = 512 * 1024 * 1024
	ExportResourceLimitMetricWithContext(&events.Event{TCPState: 1, Error: 1, Bytes: 10 * 1024 * 1024, LatencyNS: limit}, "carried-limit-ns")
	if got := testutil.ToFloat64(resourceLimitBytesGauge.WithLabelValues("memory", "carried-limit-ns")); got != limit {
		t.Fatalf("limit = %v, want the carried %v rather than one back-derived from a truncated 1%%", got, float64(limit))
	}
}

func TestExportResourceLimitMetric_DerivesTheLimitWhenNoneIsCarried(t *testing.T) {
	ExportResourceLimitMetricWithContext(&events.Event{TCPState: 0, Error: 50, Bytes: 1000}, "derived-limit-ns")
	if got := testutil.ToFloat64(resourceLimitBytesGauge.WithLabelValues("cpu", "derived-limit-ns")); got != 2000 {
		t.Fatalf("limit = %v, want 2000 derived from usage and utilization", got)
	}
}

func TestExportResourceLimitMetric_NegativeUtilizationIsNotExported(t *testing.T) {
	ExportResourceLimitMetricWithContext(&events.Event{TCPState: 1, Error: 40, Bytes: 400, LatencyNS: 1000}, "negative-ns")
	ExportResourceLimitMetricWithContext(&events.Event{TCPState: 1, Error: -1, Bytes: 0}, "negative-ns")
	if got := testutil.ToFloat64(resourceUtilizationPercentGauge.WithLabelValues("memory", "negative-ns")); got != 40 {
		t.Fatalf("utilization = %v, want the last real reading of 40", got)
	}
	if got := testutil.ToFloat64(resourceLimitBytesGauge.WithLabelValues("memory", "negative-ns")); got != 1000 {
		t.Fatalf("limit = %v, want the last real reading of 1000", got)
	}
}
