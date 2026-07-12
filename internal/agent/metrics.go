package agent

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/podtrace/podtrace/internal/logger"
)

// Metrics registers every Prometheus counter/gauge the agent exposes
// via /metrics.
type Metrics struct {
	registry *prometheus.Registry

	EventsExported  *prometheus.CounterVec
	EventsDropped   *prometheus.CounterVec
	ActiveCgroups   *prometheus.GaugeVec
	ActiveCRs       prometheus.Gauge
	ReconcileTotal  prometheus.Counter
	BackendDegraded *prometheus.GaugeVec
	CgroupsAttached prometheus.Counter
	CgroupsDetached prometheus.Counter

	ThresholdTripped    *prometheus.CounterVec
	EffectiveSampleRate *prometheus.GaugeVec
	PolicyGeneration    *prometheus.GaugeVec

	ErrorRateBreached *prometheus.CounterVec

	ProgramAttachFailures *prometheus.CounterVec
	ExporterInitFailures  *prometheus.CounterVec
	ExportDeliveryDropped *prometheus.CounterVec
	SpansBatched          *prometheus.CounterVec
	SpansDelivered        *prometheus.CounterVec

	detectorsMu sync.Mutex
	detectors   map[CRKey]*errorRateDetector

	exporterInitMu     sync.Mutex
	exporterInitLastOK map[CRKey]bool

	EnrichmentLookups       *prometheus.CounterVec
	EnrichmentCacheSize     prometheus.Gauge
	EnrichmentSnapshots     prometheus.Counter
	EnrichmentOwnerResolved *prometheus.CounterVec

	mu          sync.Mutex
	lastEvents  map[CRKey]int64
	lastDropped map[CRKey]int64

	lastEnrichHits    int64
	lastEnrichMisses  int64
	lastEnrichSnaps   int64
	lastOwnerResolved int64
	lastOwnerOrphaned int64
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
		ThresholdTripped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "podtrace_agent",
			Name:      "threshold_tripped_total",
			Help:      "Events exceeding a configured threshold, labeled by the CR that scoped them and the threshold kind (fs_slow|rtt_spike|error_rate). Stateless per-event evaluation — a counter delta over a window is a direct measure of how frequently the threshold trips.",
		}, []string{"cr_namespace", "cr_name", "threshold"}),
		EffectiveSampleRate: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "podtrace_agent",
			Name:      "effective_sample_rate",
			Help:      "Sample rate (0.0–1.0) the agent applies for each CR — the operator-resolved minimum of PodTrace.spec.samplePercent and ExporterConfig.spec.samplePercent.",
		}, []string{"cr_namespace", "cr_name"}),
		PolicyGeneration: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "podtrace_agent",
			Name:      "policy_generation",
			Help:      "metadata.generation of the source PodTrace at the time the agent loaded its bundle. Compare to .metadata.generation on the CR to verify propagation.",
		}, []string{"cr_namespace", "cr_name"}),
		ErrorRateBreached: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "podtrace_agent",
			Name:      "error_rate_breached_total",
			Help:      "Edges where a CR's rolling-window error rate transitioned from below to above its configured spec.thresholds.errorRatePercent. One increment per transition (edge-triggered), so a sustained breach does not inflate this counter.",
		}, []string{"cr_namespace", "cr_name"}),
		ProgramAttachFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "podtrace_agent",
			Name:      "program_attach_failures_total",
			Help:      "Cumulative eBPF program attach failures observed at agent startup. The program label is the BPF program symbol (closed set defined in internal/ebpf/probes); reason carries the tracer.ClassifyBackendError class (permission_denied/btf_unavailable/kernel_too_old/...). Mandatory-probe failures are also reflected by backend_degraded; this metric adds per-program granularity so fleet-wide kernel-compatibility regressions are queryable.",
		}, []string{"program", "reason"}),
		ExporterInitFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "podtrace_agent",
			Name:      "exporter_init_failures_total",
			Help:      "Per-CR exporter initialization failures, edge-triggered: one increment per transition from a previously-ok build to a failing one (or first observed failure). Reason values come from ClassifyExporterError and are a closed set. A sustained bad config does not inflate this counter — use rate() to detect new failures.",
		}, []string{"cr_namespace", "cr_name", "reason"}),
		ExportDeliveryDropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "podtrace_agent",
			Name:      "export_delivery_dropped_total",
			Help:      "Spans that were captured and handed to an exporter but FAILED to be delivered to the backend (e.g. collector unreachable). events_exported_total counts spans queued to the SDK; this counts spans the SDK could not ship. A non-zero rate here with events_exported_total climbing means the backend endpoint is wrong/down — data is being lost silently otherwise. Reason comes from ClassifyExporterError.",
		}, []string{"cr_namespace", "cr_name", "reason"}),
		SpansBatched: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "podtrace_agent",
			Name:      "spans_batched_total",
			Help:      "Spans accepted into the SDK's batch queue (post-sampling). Subtracting spans_delivered_total and export_delivery_dropped_total yields spans silently dropped by BatchSpanProcessor queue overflow, which the SDK does not otherwise expose.",
		}, []string{"cr_namespace", "cr_name"}),
		SpansDelivered: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "podtrace_agent",
			Name:      "spans_delivered_total",
			Help:      "Spans successfully delivered to the backend by an exporter ExportSpans call.",
		}, []string{"cr_namespace", "cr_name"}),
		detectors:          map[CRKey]*errorRateDetector{},
		lastEvents:         map[CRKey]int64{},
		lastDropped:        map[CRKey]int64{},
		exporterInitLastOK: map[CRKey]bool{},
	}
	reg.MustRegister(
		m.EventsExported, m.EventsDropped, m.ActiveCgroups, m.ActiveCRs,
		m.ReconcileTotal, m.BackendDegraded, m.CgroupsAttached, m.CgroupsDetached,
		m.EnrichmentLookups, m.EnrichmentCacheSize, m.EnrichmentSnapshots,
		m.EnrichmentOwnerResolved,
		m.ThresholdTripped, m.EffectiveSampleRate, m.PolicyGeneration,
		m.ErrorRateBreached,
		m.ProgramAttachFailures, m.ExporterInitFailures, m.ExportDeliveryDropped,
		m.SpansBatched, m.SpansDelivered,
	)
	return m
}

// ObserveExportDelivery records the outcome of one exporter ExportSpans
// call.
func (m *Metrics) ObserveExportDelivery(cr CRKey, spanCount int, err error) {
	if m == nil || spanCount <= 0 {
		return
	}
	if err != nil {
		if m.ExportDeliveryDropped != nil {
			m.ExportDeliveryDropped.WithLabelValues(cr.Namespace, cr.Name, ClassifyExporterError(err)).Add(float64(spanCount))
		}
		return
	}
	if m.SpansDelivered != nil {
		m.SpansDelivered.WithLabelValues(cr.Namespace, cr.Name).Add(float64(spanCount))
	}
}

// ObserveSpanBatched counts spans accepted into the batch queue (post-sampling)
// so BatchSpanProcessor queue-overflow drops become observable as
// spans_batched_total, spans_delivered_total, export_delivery_dropped_total.
func (m *Metrics) ObserveSpanBatched(cr CRKey, spanCount int) {
	if m == nil || spanCount <= 0 || m.SpansBatched == nil {
		return
	}
	m.SpansBatched.WithLabelValues(cr.Namespace, cr.Name).Add(float64(spanCount))
}

// RecordProgramAttachFailure increments program_attach_failures_total
// for a single failed probe attach.
func (m *Metrics) RecordProgramAttachFailure(program, reason string) {
	if m == nil || m.ProgramAttachFailures == nil {
		return
	}
	if reason == "" {
		reason = "unknown"
	}
	m.ProgramAttachFailures.WithLabelValues(program, reason).Inc()
}

// ObserveExporterInit records the outcome of one obtainExporter call.
func (m *Metrics) ObserveExporterInit(cr CRKey, err error) {
	if m == nil {
		return
	}
	m.exporterInitMu.Lock()
	defer m.exporterInitMu.Unlock()

	prevOK, seen := m.exporterInitLastOK[cr]
	if err == nil {
		m.exporterInitLastOK[cr] = true
		return
	}
	if !seen || prevOK {
		if m.ExporterInitFailures != nil {
			m.ExporterInitFailures.WithLabelValues(cr.Namespace, cr.Name, ClassifyExporterError(err)).Inc()
		}
	}
	m.exporterInitLastOK[cr] = false
}

// ObserveErrorRate feeds one event into the per-CR rolling-window
// error-rate detector.
func (m *Metrics) ObserveErrorRate(cr CRKey, thresholdPercent int32, isError bool) (justBreached bool) {
	if m == nil {
		return false
	}
	m.detectorsMu.Lock()
	d, ok := m.detectors[cr]
	if !ok {
		d = newErrorRateDetector(thresholdPercent)
		m.detectors[cr] = d
	} else {
		d.setThreshold(thresholdPercent)
	}
	m.detectorsMu.Unlock()

	justBreached = d.Observe(isError)
	if justBreached && m.ErrorRateBreached != nil {
		m.ErrorRateBreached.WithLabelValues(cr.Namespace, cr.Name).Inc()
	}
	return justBreached
}

// dropErrorRateDetector removes the per-CR detector when a CR is no
// longer scheduled on this node.
func (m *Metrics) dropErrorRateDetector(cr CRKey) {
	if m == nil {
		return
	}
	m.detectorsMu.Lock()
	delete(m.detectors, cr)
	m.detectorsMu.Unlock()
}

// RecordThresholdTripped bumps the per-CR-per-kind counter once for an
// event that exceeded a configured threshold.
func (m *Metrics) RecordThresholdTripped(cr CRKey, kind string) {
	if m == nil || m.ThresholdTripped == nil {
		return
	}
	m.ThresholdTripped.WithLabelValues(cr.Namespace, cr.Name, kind).Inc()
}

// ObserveEffectiveSampleRate sets the per-CR sample-rate gauge to the
// rate the bundle resolved at construction time.
func (m *Metrics) ObserveEffectiveSampleRate(cr CRKey, b *BundlePayload) {
	if m == nil || m.EffectiveSampleRate == nil {
		return
	}
	rate := 1.0
	if b != nil && b.Sample != nil {
		rate = *b.Sample
	}
	m.EffectiveSampleRate.WithLabelValues(cr.Namespace, cr.Name).Set(rate)
	if m.PolicyGeneration != nil && b != nil {
		m.PolicyGeneration.WithLabelValues(cr.Namespace, cr.Name).Set(float64(b.PolicyGeneration))
	}
}

// dropPolicyMetrics removes the per-CR policy gauges + counters when a
// CR is deleted.
func (m *Metrics) dropPolicyMetrics(cr CRKey) {
	if m == nil {
		return
	}
	lbls := prometheus.Labels{"cr_namespace": cr.Namespace, "cr_name": cr.Name}
	if m.EffectiveSampleRate != nil {
		m.EffectiveSampleRate.Delete(lbls)
	}
	if m.PolicyGeneration != nil {
		m.PolicyGeneration.Delete(lbls)
	}
	if m.ThresholdTripped != nil {
		m.ThresholdTripped.DeletePartialMatch(lbls)
	}
	if m.ErrorRateBreached != nil {
		m.ErrorRateBreached.DeletePartialMatch(lbls)
	}
	if m.ExporterInitFailures != nil {
		m.ExporterInitFailures.DeletePartialMatch(lbls)
	}
	m.dropErrorRateDetector(cr)
	m.exporterInitMu.Lock()
	delete(m.exporterInitLastOK, cr)
	m.exporterInitMu.Unlock()
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

// OnTargetError logs a backend target-reconcile failure so an attach problem
// is visible as an attach problem.
func (o *metricsEngineObserver) OnTargetError(stage string, err error) {
	if err == nil {
		return
	}
	logger.Warn("tracer target reconcile failed",
		zap.String("stage", stage),
		zap.Error(err),
	)
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
		m.dropPolicyMetrics(key)
	}
	for _, rule := range rules {
		if m.EffectiveSampleRate != nil {
			rate := 1.0
			if pct := rule.Policy.EffectiveSamplePercent; pct != nil {
				rate = float64(*pct) / 100.0
			}
			m.EffectiveSampleRate.With(prometheus.Labels{
				"cr_namespace": rule.Key.Namespace,
				"cr_name":      rule.Key.Name,
			}).Set(rate)
		}
		if m.PolicyGeneration != nil {
			m.PolicyGeneration.With(prometheus.Labels{
				"cr_namespace": rule.Key.Namespace,
				"cr_name":      rule.Key.Name,
			}).Set(float64(rule.Policy.Generation))
		}
	}
}
