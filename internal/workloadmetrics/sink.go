package workloadmetrics

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/gma1k/podtrace/internal/events"
)

// Options configures a Sink.
type Options struct {
	SeriesBudget int

	NativeHistograms bool

	IncludePodLabel bool

	IncludeProcessLabel bool

	Lookup func(cgroupID uint64) (events.K8sMetadata, bool)

	ResolvePeer func(peerIP string, peerPort uint16) (PeerIdentity, bool)

	OnBudgetExhausted func(budget int)

	Now func() time.Time

	SemanticConventions bool

	AttributeCardinality int
}

// seriesEntry records enough about an admitted series to delete it later.
type seriesEntry struct {
	family   string
	labels   []string
	lastSeen time.Time
}

// Sink aggregates events into the continuous surface. It satisfies
// tracer.Exporter, so the agent registers it alongside the per-CR router
// and the engine fans out to both.
type Sink struct {
	c      *collectors
	sc     *semconvCollectors
	edges  *edgeCollectors
	lookup func(uint64) (events.K8sMetadata, bool)

	resolvePeer func(string, uint16) (PeerIdentity, bool)

	own *prometheus.Registry

	includePod     bool
	includeProcess bool

	mu        sync.Mutex
	seen      map[string]*seriesEntry
	budget    int
	exhausted bool

	now func() time.Time

	onExhausted func(budget int)
}

// New builds a Sink and registers its collectors with reg.
func New(reg prometheus.Registerer, opts Options) (*Sink, error) {
	c := newCollectors(opts)
	if err := c.register(reg); err != nil {
		return nil, err
	}

	var sc *semconvCollectors
	if opts.SemanticConventions {
		limit := opts.AttributeCardinality
		if limit == 0 {
			limit = defaultAttributeCardinality
		}
		sc = newSemconvCollectors(opts.NativeHistograms, limit)
		if err := sc.register(reg); err != nil {
			return nil, fmt.Errorf("register semantic-convention metrics: %w", err)
		}
	}
	var edges *edgeCollectors
	if opts.ResolvePeer != nil {
		limit := opts.AttributeCardinality
		if limit == 0 {
			limit = defaultAttributeCardinality
		}
		edges = newEdgeCollectors(opts.NativeHistograms, limit)
		if err := edges.register(reg); err != nil {
			return nil, fmt.Errorf("register service-map metrics: %w", err)
		}
	}

	own := prometheus.NewRegistry()
	own.MustRegister(c.all()...)
	if sc != nil {
		own.MustRegister(sc.all()...)
	}
	if edges != nil {
		own.MustRegister(edges.all()...)
	}

	clock := opts.Now
	if clock == nil {
		clock = time.Now
	}
	return &Sink{
		c:              c,
		sc:             sc,
		edges:          edges,
		resolvePeer:    opts.ResolvePeer,
		own:            own,
		lookup:         opts.Lookup,
		includePod:     opts.IncludePodLabel,
		includeProcess: opts.IncludeProcessLabel,
		seen:           make(map[string]*seriesEntry),
		budget:         opts.SeriesBudget,
		onExhausted:    opts.OnBudgetExhausted,
		now:            clock,
	}, nil
}

func (s *Sink) Name() string { return "workload-metrics" }

// Gather returns the workload surface in Prometheus exposition form,
// making the Sink a prometheus.Gatherer over its own families only.
func (s *Sink) Gather() ([]*dto.MetricFamily, error) {
	if s == nil || s.own == nil {
		return nil, nil
	}
	return s.own.Gather()
}

// Close releases nothing; the collectors live as long as the registry.
func (s *Sink) Close(context.Context) error { return nil }

// admit reports whether a series may be observed, enforcing the budget.
func (s *Sink) admit(family string, labelValues []string) bool {
	var key strings.Builder
	key.WriteString(family)
	for _, v := range labelValues {
		key.WriteByte(0)
		key.WriteString(v)
	}
	k := key.String()

	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.seen[k]; ok {
		existing.lastSeen = s.now()
		return true
	}
	if s.budget > 0 && len(s.seen) >= s.budget {
		s.c.seriesDropped.WithLabelValues(family).Inc()
		notify := !s.exhausted
		s.exhausted = true
		if notify && s.onExhausted != nil {
			s.onExhausted(s.budget)
		}
		return false
	}
	s.seen[k] = &seriesEntry{
		family:   family,
		labels:   append([]string(nil), labelValues...),
		lastSeen: s.now(),
	}
	s.c.seriesActive.Set(float64(len(s.seen)))
	return true
}

// Reap deletes series that have not been observed for longer than maxIdle,
// returning how many it removed.
func (s *Sink) Reap(maxIdle time.Duration) int {
	if maxIdle <= 0 {
		return 0
	}

	cutoff := s.now().Add(-maxIdle)

	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for key, entry := range s.seen {
		if entry.lastSeen.After(cutoff) {
			continue
		}
		if s.deleteSeries(entry) {
			removed++
		}
		delete(s.seen, key)
	}
	if removed > 0 {
		s.c.seriesReaped.Add(float64(removed))
		s.c.seriesActive.Set(float64(len(s.seen)))
		if s.budget <= 0 || len(s.seen) < s.budget {
			s.exhausted = false
		}
	}
	return removed
}

// deleteSeries removes one series from whichever collector owns its family.
func (s *Sink) deleteSeries(entry *seriesEntry) bool {
	if h, ok := s.c.histogramFor(entry.family); ok {
		return h.DeleteLabelValues(entry.labels...)
	}
	if c, ok := s.c.counterFor(entry.family); ok {
		return c.DeleteLabelValues(entry.labels...)
	}
	return false
}

func (s *Sink) observe(h *prometheus.HistogramVec, family string, labelValues []string, seconds float64) {
	if !s.admit(family, labelValues) {
		return
	}
	h.WithLabelValues(labelValues...).Observe(seconds)
}

func (s *Sink) add(c *prometheus.CounterVec, family string, labelValues []string, delta float64) {
	if !s.admit(family, labelValues) {
		return
	}
	c.WithLabelValues(labelValues...).Add(delta)
}

// Export aggregates a batch. It never returns an error: a metrics plane
// that fails a batch would stall the engine's fan-out for every other
// exporter, and a dropped observation is already visible through
// metrics_events_total and metrics_series_dropped_total.
func (s *Sink) Export(_ context.Context, batch []*events.Event) error {
	for _, e := range batch {
		if e == nil {
			continue
		}
		base, ok := s.baseLabelValues(e)
		if !ok {
			s.c.eventsTotal.WithLabelValues("unattributed").Inc()
			continue
		}
		if s.record(e, base) {
			s.c.eventsTotal.WithLabelValues("aggregated").Inc()
		} else {
			s.c.eventsTotal.WithLabelValues("ignored").Inc()
		}
	}
	return nil
}

// baseLabelValues projects an event's pod metadata onto the base label
// set, resolving it through Lookup when the event arrives unenriched.
func (s *Sink) baseLabelValues(e *events.Event) ([]string, bool) {
	meta, ok := s.metadataFor(e)
	if !ok {
		return nil, false
	}
	if meta.Namespace == "" || meta.WorkloadName == "" {
		return nil, false
	}

	values := make([]string, 0, len(defaultBaseLabels)+2)
	values = append(values,
		meta.Namespace,
		meta.WorkloadName,
		orUnknown(meta.WorkloadKind),
		orUnknown(meta.ContainerName),
	)
	if s.includePod {
		values = append(values, orUnknown(meta.PodName))
	}
	if s.includeProcess {
		values = append(values, orUnknown(e.ProcessName))
	}
	return values, true
}

func (s *Sink) metadataFor(e *events.Event) (events.K8sMetadata, bool) {
	if e.K8s != nil && !e.K8s.IsZero() {
		return *e.K8s, true
	}
	if s.lookup == nil {
		return events.K8sMetadata{}, false
	}
	return s.lookup(e.CgroupID)
}

func orUnknown(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

func appendLabels(base []string, extra ...string) []string {
	out := make([]string, 0, len(base)+len(extra))
	out = append(out, base...)
	out = append(out, extra...)
	return out
}

// record routes one event to its family. Returns false when no family
// maps to the event type, which is expected: this surface deliberately
// covers golden signals rather than every event podtrace can emit.
func (s *Sink) record(e *events.Event, base []string) bool {
	seconds := e.Latency().Seconds()

	if e.IsError() {
		s.add(s.c.errors, "errors_total", appendLabels(base, errorKind(e.Type)), 1)
	}

	switch e.Type {
	case events.EventHTTPReq, events.EventFastCGIReq:
		return true

	case events.EventHTTPResp, events.EventHTTP3, events.EventGRPCMethod,
		events.EventFastCGIResp, events.EventRedisCmd, events.EventMemcachedCmd,
		events.EventKafkaProduce, events.EventKafkaFetch, events.EventDBQuery:
		protocol := protocolLabel(e)
		s.add(s.c.l7Requests, "l7_requests_total",
			appendLabels(base, protocol, statusClass(e), outcome(e)), 1)
		s.observe(s.c.l7Duration, "l7_request_duration_seconds",
			appendLabels(base, protocol), seconds)
		s.recordSemconv(e, seconds)
		s.recordEdgeL7(e, outcome(e), seconds)
		return true

	case events.EventTCPSend, events.EventTCPRecv, events.EventUDPSend, events.EventUDPRecv:
		direction, transport := networkDimensions(e.Type)
		s.observe(s.c.networkLatency, "network_latency_seconds",
			appendLabels(base, direction, transport), seconds)
		if e.Bytes > 0 {
			s.add(s.c.networkBytes, "network_bytes_total",
				appendLabels(base, direction, transport), float64(e.Bytes))
		}
		s.recordEdgeNetwork(e, direction)
		return true

	case events.EventDNS, events.EventDNSQuery:
		s.observe(s.c.dnsLatency, "dns_latency_seconds", base, seconds)
		return true

	case events.EventRead, events.EventWrite, events.EventFsync,
		events.EventOpen, events.EventClose, events.EventUnlink, events.EventRename:
		operation := filesystemOperation(e.Type)
		s.observe(s.c.filesystemLatency, "filesystem_latency_seconds",
			appendLabels(base, operation), seconds)
		if e.Bytes > 0 && (e.Type == events.EventRead || e.Type == events.EventWrite) {
			s.add(s.c.filesystemBytes, "filesystem_bytes_total",
				appendLabels(base, operation), float64(e.Bytes))
		}
		return true

	case events.EventSchedSwitch:
		s.observe(s.c.cpuBlocked, "cpu_blocked_seconds", base, seconds)
		return true

	case events.EventTLSHandshake:
		s.observe(s.c.tlsHandshakeDuration, "tls_handshake_duration_seconds", base, seconds)
		return true

	default:
		return false
	}
}

func (s *Sink) recordSemconv(e *events.Event, seconds float64) {
	if s.sc == nil {
		return
	}
	meta, ok := s.metadataFor(e)
	if !ok {
		return
	}
	id := semconvIdentity(meta)

	switch e.Type {
	case events.EventHTTPResp, events.EventHTTP3:
		s.observe(s.sc.httpDuration, semconvHTTPDuration,
			appendLabels(id, httpRequestMethod(e), statusCodeLabel(e), networkProtocolName(e)), seconds)

	case events.EventGRPCMethod:
		method := s.sc.methodValues.bound(firstLine(e.Target))
		s.observe(s.sc.rpcDuration, semconvRPCDuration,
			appendLabels(id, rpcSystem(e.Type), method), seconds)

	case events.EventRedisCmd, events.EventMemcachedCmd, events.EventDBQuery:
		op := s.sc.operationValues.bound(firstLine(e.Details))
		s.observe(s.sc.dbDuration, semconvDBDuration,
			appendLabels(id, dbSystem(e.Type), op), seconds)
	}
}
