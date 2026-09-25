package operator

import (
	"strconv"
	"testing"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestAgentPodsAdvertiseTheirMetricsEndpoint(t *testing.T) {
	spec := buildAgentDaemonSetSpec(tc(func(*podtracev1alpha1.TracerConfig) {}), "podtrace-system")
	ann := spec.Template.Annotations

	if ann["prometheus.io/scrape"] != "true" || ann["prometheus.io/path"] != "/metrics" {
		t.Errorf("agent pod annotations = %v, want prometheus.io/scrape=true and path /metrics.\n\n"+
			"Annotation-based scrapers (the community Prometheus chart, the OpenTelemetry "+
			"Collector, Datadog) find the continuous plane only through these; without them "+
			"a cluster without the Prometheus Operator scrapes nothing.", ann)
	}

	var metricsPort int32
	for _, p := range spec.Template.Spec.Containers[0].Ports {
		if p.Name == "metrics" {
			metricsPort = p.ContainerPort
		}
	}
	if metricsPort == 0 {
		t.Fatal("the agent container exposes no port named metrics; the PodMonitor selects it by that name")
	}
	if got := ann["prometheus.io/port"]; got != strconv.Itoa(int(metricsPort)) {
		t.Errorf("prometheus.io/port = %q, but the metrics port is %d; a scraper would dial the wrong port", got, metricsPort)
	}
}
