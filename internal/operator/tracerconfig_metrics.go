package operator

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Fleet-partition Prometheus surface.
var (
	tracerConfigMatchedNodes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "podtrace_operator",
		Name:      "tracerconfig_matched_nodes",
		Help: "Nodes each TracerConfig's scheduling constraints select. " +
			"Summing across configs exceeds the cluster node count exactly " +
			"when fleets overlap.",
	}, []string{"tracer_config"})

	tracerConfigContestedNodes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "podtrace_operator",
		Name:      "tracerconfig_contested_nodes",
		Help: "Nodes a TracerConfig selects that another TracerConfig also " +
			"selects. Non-zero means two agent DaemonSets are attached on " +
			"those nodes and every event observed there is counted twice; " +
			"alert on > 0.",
	}, []string{"tracer_config"})
)

func init() {
	ctrlmetrics.Registry.MustRegister(tracerConfigMatchedNodes, tracerConfigContestedNodes)
}

// forgetTracerConfigMetrics drops a deleted config's gauge series so a
// removed fleet does not leave a stale contested-nodes reading behind.
func forgetTracerConfigMetrics(name string) {
	tracerConfigMatchedNodes.DeleteLabelValues(name)
	tracerConfigContestedNodes.DeleteLabelValues(name)
}
