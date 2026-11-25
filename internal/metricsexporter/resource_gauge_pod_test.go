package metricsexporter

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/gma1k/podtrace/internal/events"
)

func TestResourceEventsAreKeyedByTheirSourcePod(t *testing.T) {
	HandleEventWithContext(&events.Event{Type: events.EventResourceLimit, TCPState: 1, Error: 70, Bytes: 70, LatencyNS: 100},
		map[string]interface{}{"namespace": "pod-keyed-ns", "source_pod": "web-1"})
	HandleEventWithContext(&events.Event{Type: events.EventResourceLimit, TCPState: 1, Error: 20, Bytes: 20, LatencyNS: 100,
		K8s: &events.K8sMetadata{PodName: "web-2"}},
		map[string]interface{}{"namespace": "pod-keyed-ns"})

	if got := testutil.ToFloat64(resourceUtilizationPercentGauge.WithLabelValues("memory", "pod-keyed-ns", "web-1")); got != 70 {
		t.Errorf("web-1 utilization = %v, want 70", got)
	}
	if got := testutil.ToFloat64(resourceUtilizationPercentGauge.WithLabelValues("memory", "pod-keyed-ns", "web-2")); got != 20 {
		t.Errorf("web-2 utilization = %v, want 20 rather than web-1's reading overwritten", got)
	}
}

func TestDeleteResourceMetricsRemovesOnlyThatPod(t *testing.T) {
	ExportResourceMetrics("memory", "delete-ns", "keep", 100, 10, 10, 0)
	ExportResourceMetrics("memory", "delete-ns", "drop", 100, 20, 20, 0)
	ExportResourceMetrics("cpu", "delete-ns", "drop", 100, 20, 20, 0)

	DeleteResourceMetrics("delete-ns", "drop")

	if got := testutil.CollectAndCount(resourceUtilizationPercentGauge); got == 0 {
		t.Fatal("no series left at all")
	}
	if got := testutil.ToFloat64(resourceUtilizationPercentGauge.WithLabelValues("memory", "delete-ns", "keep")); got != 10 {
		t.Errorf("kept pod utilization = %v, want 10", got)
	}
	for _, rt := range []string{"memory", "cpu"} {
		if resourceUtilizationPercentGauge.DeleteLabelValues(rt, "delete-ns", "drop") {
			t.Errorf("%s series of the deleted pod survived", rt)
		}
	}
}

func TestSourcePodOfWithoutContextOrMetadataIsEmpty(t *testing.T) {
	if got := sourcePodOf(nil, nil); got != "" {
		t.Errorf("sourcePodOf(nil, nil) = %q", got)
	}
	if got := sourcePodOf(&events.Event{}, nil); got != "" {
		t.Errorf("sourcePodOf without metadata = %q", got)
	}
}
