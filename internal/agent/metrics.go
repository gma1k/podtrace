package agent

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics registers every Prometheus counter/gauge the agent exposes
// via /metrics. Counters are organised by (cr_namespace, cr_name)
// labels so users can graph per-CR throughput and drops.
//
// Registration is done against a dedicated Registry (not the default)
// so the agent's /metrics output is stable: a test that imports any
// package registering against the default registry does not pollute
// the agent's scrape surface.
type Metrics struct {
	registry *prometheus.Registry

	EventsExported  *prometheus.CounterVec
	EventsDropped   *prometheus.CounterVec
	ActiveCgroups   *prometheus.GaugeVec
	ActiveCRs       prometheus.Gauge
	ReconcileTotal  prometheus.Counter
	BackendDegraded *prometheus.GaugeVec

	// lastEvents / lastDropped cache the previously-observed cumulative
	// totals per CR so each refresh can emit the delta to the
	// monotonic Prometheus counters.
	mu          sync.Mutex
	lastEvents  map[CRKey]int64
	lastDropped map[CRKey]int64
}

// NewMetrics constructs the full metric surface and registers it
// against a fresh Registry. The returned Handler can be mounted on any
// HTTP server.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		registry: reg,
		EventsExported: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "podtrace_agent",
			Name:      "events_exported_total",
			Help:      "Events successfully handed off to at least one exporter, labeled by the CR that scoped them.",
		}, []string{"cr_namespace", "cr_name"}),
		EventsDropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "podtrace_agent",
			Name:      "events_dropped_total",
			Help:      "Events a CR claimed but whose exporter returned an error (non-fatal, retried via stats only).",
		}, []string{"cr_namespace", "cr_name"}),
		ActiveCgroups: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "podtrace_agent",
			Name:      "active_cgroups",
			Help:      "Cgroups the tracer is currently attached to on behalf of each CR.",
		}, []string{"cr_namespace", "cr_name"}),
		ActiveCRs: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "podtrace_agent",
			Name:      "active_crs",
			Help:      "Number of PodTrace CRs currently scheduled on this node.",
		}),
		ReconcileTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "podtrace_agent",
			Name:      "reconcile_total",
			Help:      "Reconcile ticks performed on the router regardless of outcome.",
		}),
		// BackendDegraded is set to 1 when buildBackend falls back to the
		// noop tracer.
		BackendDegraded: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "podtrace_agent",
			Name:      "backend_degraded",
			Help:      "1 when this agent fell back to the noop tracer because the real eBPF backend failed to load; reason label carries a stable error class.",
		}, []string{"reason"}),
		lastEvents:  map[CRKey]int64{},
		lastDropped: map[CRKey]int64{},
	}
	reg.MustRegister(m.EventsExported, m.EventsDropped, m.ActiveCgroups, m.ActiveCRs, m.ReconcileTotal, m.BackendDegraded)
	return m
}

// Handler returns a promhttp.Handler bound to this Metrics' registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// RefreshFromRouter walks the router's rule set + stats table and
// updates every metric to the current snapshot. Called on each status
// writer tick so metrics do not drift from status.
func (m *Metrics) RefreshFromRouter(router *Router) {
	rules := router.RulesSnapshot()
	stats := router.Stats().snapshot()

	m.mu.Lock()
	defer m.mu.Unlock()

	m.ActiveCRs.Set(float64(len(rules)))

	seen := make(map[CRKey]struct{}, len(rules))
	for _, rule := range rules {
		seen[rule.Key] = struct{}{}
		lbls := prometheus.Labels{
			"cr_namespace": rule.Key.Namespace,
			"cr_name":      rule.Key.Name,
		}
		m.ActiveCgroups.With(lbls).Set(float64(len(rule.CgroupIDs)))

		c := stats[rule.Key]
		if delta := c.Events - m.lastEvents[rule.Key]; delta > 0 {
			m.EventsExported.With(lbls).Add(float64(delta))
		}
		if delta := c.Dropped - m.lastDropped[rule.Key]; delta > 0 {
			m.EventsDropped.With(lbls).Add(float64(delta))
		}
		m.lastEvents[rule.Key] = c.Events
		m.lastDropped[rule.Key] = c.Dropped
	}

	// Drop cgroup gauge and cached deltas for CRs that disappeared —
	// otherwise /metrics keeps emitting zero gauges for stale CR names
	// forever and cardinality grows without bound.
	for key := range m.lastEvents {
		if _, ok := seen[key]; ok {
			continue
		}
		lbls := prometheus.Labels{"cr_namespace": key.Namespace, "cr_name": key.Name}
		m.ActiveCgroups.Delete(lbls)
		delete(m.lastEvents, key)
		delete(m.lastDropped, key)
	}
}
