package metricsexporter

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/gma1k/podtrace/internal/config"
)

func TestRecordError_BoundsErrorCodeCardinality(t *testing.T) {
	const eventType = "grpc-cardinality-test"
	for i := 1; i <= config.MetricsLabelLimit+50; i++ {
		RecordError(eventType, int32(i))
	}
	if testutil.ToFloat64(errorRateCounter.WithLabelValues(eventType, "other")) == 0 {
		t.Fatal("a flood of distinct error codes must collapse into the 'other' label, not mint one series each")
	}
}
