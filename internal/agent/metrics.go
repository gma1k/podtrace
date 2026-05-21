package agent

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics registers every Prometheus counter/gauge the agent exposes
// via /metrics.
type Metrics struct {
	registry *prometheus.Registry

	EventsExported   *prometheus.CounterVec
	EventsDropped    *prometheus.CounterVec
	ActiveCgroups    *prometheus.GaugeVec
	ActiveCRs        prometheus.Gauge
	ReconcileTotal   prometheus.Counter
	BackendDegraded  *prometheus.GaugeVec
	CgroupsAttached  prometheus.Counter
	CgroupsDetached  prometheus.Counter

	EnrichmentLookups       *prometheus.CounterVec
	EnrichmentCacheSize     prometheus.Gauge
	EnrichmentSnapshots     prometheus.Counter
	EnrichmentOwnerResolved *prometheus.CounterVec

	mu          sync.Mutex
	lastEvents  map[CRKey]int64
	lastDropped map[CRKey]int64

	lastEnrichHits     int64
	lastEnrichMisses   int64
	lastEnrichSnaps    int64
	lastOwnerResolved  int64
	lastOwnerOrphaned  int64
}

// NewMetrics constructs the full metric surface and registers it
// against a fresh Registry.
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
		BackendDegraded: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "podtrace_agent",
			Name:      "backend_degraded",
			Help:      "1 when this agent fell back to the noop tracer because the real eBPF backend failed to load; reason label carries a stable error class.",
		}, []string{"reason"}),
		CgroupsAttached: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "podtrace_agent",
			Name:      "cgroups_attached_total",
			Help:      "Cumulative cgroups added to the tracer filter set.",
		}),
		CgroupsDetached: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "podtrace_agent",
			Name:      "cgroups_detached_total",
			Help:      "Cumulative cgroups removed from the tracer filter set (pod churn).",
		}),
		EnrichmentLookups: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "podtrace_agent",
			Name:      "enrichment_lookups_total",
			Help:      "Cgroup→k8s metadata lookups performed on the export hot path. Misses are events that arrived before the reconciler observed the pod; a sustained miss rate >1%% indicates the enricher is not keeping up with pod churn.",
		}, []string{"result"}),
		EnrichmentCacheSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "podtrace_agent",
			Name:      "enrichment_cache_size",
			Help:      "Cgroup IDs currently held by the k8s metadata cache. Roughly equals (local pods × (1 + containers per pod)).",
		}),
		EnrichmentSnapshots: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "podtrace_agent",
			Name:      "enrichment_snapshots_total",
			Help:      "Atomic replacements of the enrichment cache (one per Reconcile pass that observed pods).",
		}),
		EnrichmentOwnerResolved: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "podtrace_agent",
			Name:      "enrichment_owner_resolution_total",
			Help:      "Workload-owner resolution outcomes. result=resolved means OwnerReferences yielded a workload kind+name; result=orphaned means the pod had no controller ref and degraded to kind=Pod.",
		}, []string{"result"}),
		lastEvents:  map[CRKey]int64{},
		lastDropped: map[CRKey]int64{},
	}
	reg.MustRegister(
		m.EventsExported, m.EventsDropped, m.ActiveCgroups, m.ActiveCRs,
		m.ReconcileTotal, m.BackendDegraded, m.CgroupsAttached, m.CgroupsDetached,
		m.EnrichmentLookups, m.EnrichmentCacheSize, m.EnrichmentSnapshots,
		m.EnrichmentOwnerResolved,
	)
	return m
}

// RefreshFromEnricher emits the deltas from the enricher's atomic
// counters to the Prometheus metric set.
func (m *Metrics) RefreshFromEnricher(e *PodEnricher) {
	if m == nil || e == nil {
		return
	}
	stats := e.Stats()
	m.mu.Lock()
	defer m.mu.Unlock()

	if delta := stats.Hits - m.lastEnrichHits; delta > 0 {
		m.EnrichmentLookups.WithLabelValues("hit").Add(float64(delta))
	}
	if delta := stats.Misses - m.lastEnrichMisses; delta > 0 {
		m.EnrichmentLookups.WithLabelValues("miss").Add(float64(delta))
	}
	if delta := stats.Snapshots - m.lastEnrichSnaps; delta > 0 {
		m.EnrichmentSnapshots.Add(float64(delta))
	}
	if delta := stats.OwnerResolved - m.lastOwnerResolved; delta > 0 {
		m.EnrichmentOwnerResolved.WithLabelValues("resolved").Add(float64(delta))
	}
	if delta := stats.OwnerOrphaned - m.lastOwnerOrphaned; delta > 0 {
		m.EnrichmentOwnerResolved.WithLabelValues("orphaned").Add(float64(delta))
	}
	m.lastEnrichHits = stats.Hits
	m.lastEnrichMisses = stats.Misses
	m.lastEnrichSnaps = stats.Snapshots
	m.lastOwnerResolved = stats.OwnerResolved
	m.lastOwnerOrphaned = stats.OwnerOrphaned

	m.EnrichmentCacheSize.Set(float64(stats.CacheSize))
}

// Handler returns a promhttp.Handler bound to this Metrics' registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// EngineObserver returns an adapter that bridges the engine's
// tracer.EngineObserver callbacks into this Metrics' Prometheus
// counters.
func (m *Metrics) EngineObserver() *metricsEngineObserver {
	return &metricsEngineObserver{m: m}
}

type metricsEngineObserver struct {
	m *Metrics
}

func (o *metricsEngineObserver) OnCgroupsAttached(n int) {
	if n <= 0 {
		return
	}
	o.m.CgroupsAttached.Add(float64(n))
}

func (o *metricsEngineObserver) OnCgroupsDetached(n int) {
	if n <= 0 {
		return
	}
	o.m.CgroupsDetached.Add(float64(n))
}

// RefreshFromRouter walks the router's rule set + stats table and
// updates every metric to the current snapshot.
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
