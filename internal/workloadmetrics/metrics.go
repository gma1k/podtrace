// Package workloadmetrics aggregates observed traffic into the continuous
// Prometheus surface documented in docs/continuous-metrics.md.
package workloadmetrics

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

const metricPrefix = "podtrace_workload_"

// latencyBuckets spans 500us to 30s in twelve buckets.
var latencyBuckets = []float64{
	0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 5, 30,
}

var defaultBaseLabels = []string{"namespace", "workload", "workload_kind", "container"}

// baseLabelNames returns the base label set for the given options.
func baseLabelNames(opts Options) []string {
	names := make([]string, 0, len(defaultBaseLabels)+2)
	names = append(names, defaultBaseLabels...)
	if opts.IncludePodLabel {
		names = append(names, "pod")
	}
	if opts.IncludeProcessLabel {
		names = append(names, "process")
	}
	return names
}

// collectors is the complete set of metrics this package exposes.
type collectors struct {
	l7Requests *prometheus.CounterVec
	l7Duration *prometheus.HistogramVec

	networkLatency *prometheus.HistogramVec
	networkBytes   *prometheus.CounterVec

	dnsLatency *prometheus.HistogramVec

	filesystemLatency *prometheus.HistogramVec
	filesystemBytes   *prometheus.CounterVec

	cpuBlocked *prometheus.HistogramVec

	tlsHandshakeDuration *prometheus.HistogramVec

	errors *prometheus.CounterVec

	eventsTotal   *prometheus.CounterVec
	seriesDropped *prometheus.CounterVec
	seriesActive  prometheus.Gauge
	seriesReaped  prometheus.Counter
}

// familyLookup resolves the short family name recorded against an admitted
// series back to the collector that owns it, so the series can be deleted
// when the workload behind it is gone.
func (c *collectors) histogramFor(family string) (*prometheus.HistogramVec, bool) {
	switch family {
	case "l7_request_duration_seconds":
		return c.l7Duration, true
	case "network_latency_seconds":
		return c.networkLatency, true
	case "dns_latency_seconds":
		return c.dnsLatency, true
	case "filesystem_latency_seconds":
		return c.filesystemLatency, true
	case "cpu_blocked_seconds":
		return c.cpuBlocked, true
	case "tls_handshake_duration_seconds":
		return c.tlsHandshakeDuration, true
	default:
		return nil, false
	}
}

func (c *collectors) counterFor(family string) (*prometheus.CounterVec, bool) {
	switch family {
	case "l7_requests_total":
		return c.l7Requests, true
	case "network_bytes_total":
		return c.networkBytes, true
	case "filesystem_bytes_total":
		return c.filesystemBytes, true
	case "errors_total":
		return c.errors, true
	default:
		return nil, false
	}
}

func histogramOpts(name, help string, native bool) prometheus.HistogramOpts {
	opts := prometheus.HistogramOpts{
		Name:    metricPrefix + name,
		Help:    help,
		Buckets: latencyBuckets,
	}
	if native {
		opts.NativeHistogramBucketFactor = 1.1
		opts.NativeHistogramMaxBucketNumber = 160
	}
	return opts
}

func newCollectors(opts Options) *collectors {
	native := opts.NativeHistograms
	base := baseLabelNames(opts)
	withBase := func(extra ...string) []string {
		out := make([]string, 0, len(base)+len(extra))
		out = append(out, base...)
		out = append(out, extra...)
		return out
	}
	return &collectors{
		l7Requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricPrefix + "l7_requests_total",
			Help: "Application-layer requests observed, by protocol and outcome. Use rate() for throughput and the status_class label for error ratio.",
		}, withBase("protocol", "status_class", "outcome")),

		l7Duration: prometheus.NewHistogramVec(
			histogramOpts("l7_request_duration_seconds",
				"Distribution of application-layer request durations, by protocol.", native),
			withBase("protocol"),
		),

		networkLatency: prometheus.NewHistogramVec(
			histogramOpts("network_latency_seconds",
				"Distribution of socket send and receive latency.", native),
			withBase("direction", "transport"),
		),

		networkBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricPrefix + "network_bytes_total",
			Help: "Bytes transferred over sockets. Use rate() for bytes per second.",
		}, withBase("direction", "transport")),

		dnsLatency: prometheus.NewHistogramVec(
			histogramOpts("dns_latency_seconds",
				"Distribution of DNS resolution latency.", native),
			withBase(),
		),

		filesystemLatency: prometheus.NewHistogramVec(
			histogramOpts("filesystem_latency_seconds",
				"Distribution of filesystem operation latency, by operation.", native),
			withBase("operation"),
		),

		filesystemBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricPrefix + "filesystem_bytes_total",
			Help: "Bytes read from and written to the filesystem. Use rate() for bytes per second.",
		}, withBase("operation")),

		cpuBlocked: prometheus.NewHistogramVec(
			histogramOpts("cpu_blocked_seconds",
				"Distribution of time spent off-CPU waiting to be scheduled.", native),
			withBase(),
		),

		tlsHandshakeDuration: prometheus.NewHistogramVec(
			histogramOpts("tls_handshake_duration_seconds",
				"Distribution of TLS handshake durations.", native),
			withBase(),
		),

		errors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricPrefix + "errors_total",
			Help: "Observed operations that failed, by event kind.",
		}, withBase("kind")),

		eventsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricPrefix + "metrics_events_total",
			Help: "Events reaching this plane, by outcome: aggregated, unattributed (no pod metadata), or ignored (no family maps to the event type).",
		}, []string{"outcome"}),

		seriesDropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricPrefix + "metrics_series_dropped_total",
			Help: "Observations discarded because admitting a new series would exceed the per-node budget, by family.",
		}, []string{"family"}),

		seriesActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: metricPrefix + "metrics_series_active",
			Help: "Distinct label combinations currently held by this plane, counted against the per-node budget.",
		}),

		seriesReaped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: metricPrefix + "metrics_series_reaped_total",
			Help: "Series removed after their workload stopped being observed, freeing budget.",
		}),
	}
}

func (c *collectors) all() []prometheus.Collector {
	return []prometheus.Collector{
		c.l7Requests,
		c.l7Duration,
		c.networkLatency,
		c.networkBytes,
		c.dnsLatency,
		c.filesystemLatency,
		c.filesystemBytes,
		c.cpuBlocked,
		c.tlsHandshakeDuration,
		c.errors,
		c.eventsTotal,
		c.seriesDropped,
		c.seriesActive,
		c.seriesReaped,
	}
}

func (c *collectors) register(reg prometheus.Registerer) error {
	for _, collector := range c.all() {
		if err := reg.Register(collector); err != nil {
			return fmt.Errorf("register workload metrics: %w", err)
		}
	}
	return nil
}
