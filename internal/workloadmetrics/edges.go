package workloadmetrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/events"
)

// The service map, as metrics rather than as a datastore.
//
// A topology view normally needs a relay, a store and a cluster-wide
// aggregation tier. It does not have to: if every request carries both ends
// of the edge, the map is a PromQL expression and Grafana's node graph
// already knows how to draw it.
//
//	sum by (workload, target_service) (
//	    rate(podtrace_workload_edge_requests_total[5m])
//	)
const (
	edgeRequestsTotal   = "edge_requests_total"
	edgeRequestDuration = "edge_request_duration_seconds"
	edgeBytesTotal      = "edge_bytes_total"
)

// The byte counter is what puts non-L7 flows on the map: a database, a
// cache, anything over TLS podtrace cannot read.
type PeerIdentity struct {
	Service   string
	Namespace string
}

var edgeLabels = []string{
	"namespace",
	"workload",
	"target_namespace",
	"target_service",
}

func withEdgeLabels(extra ...string) []string {
	out := make([]string, 0, len(edgeLabels)+len(extra))
	out = append(out, edgeLabels...)
	out = append(out, extra...)
	return out
}

// edgeCollectors holds the topology families.
type edgeCollectors struct {
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
	bytes    *prometheus.CounterVec

	targets *boundedValues
}

func newEdgeCollectors(native bool, limit int) *edgeCollectors {
	return &edgeCollectors{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricPrefix + edgeRequestsTotal,
			Help: "L7 requests between a workload and the service it called, for the service map.",
		}, withEdgeLabels("outcome")),
		duration: prometheus.NewHistogramVec(
			histogramOpts(edgeRequestDuration,
				"Duration of L7 requests between a workload and the service it called.", native),
			withEdgeLabels(),
		),
		bytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: metricPrefix + edgeBytesTotal,
			Help: "Bytes moved between a workload and its peer, so the map covers non-L7 flows.",
		}, withEdgeLabels("direction")),
		targets: newBoundedValues(limit),
	}
}

func (c *edgeCollectors) all() []prometheus.Collector {
	return []prometheus.Collector{c.requests, c.duration, c.bytes}
}

func (c *edgeCollectors) register(reg prometheus.Registerer) error {
	for _, collector := range c.all() {
		if err := reg.Register(collector); err != nil {
			return err
		}
	}
	return nil
}

// edgeIdentity projects an event's near and far ends onto edgeLabels, and
// reports false when there is no edge to record.
func (s *Sink) edgeIdentity(e *events.Event) ([]string, bool) {
	if s.edges == nil || s.resolvePeer == nil {
		return nil, false
	}
	meta, ok := s.metadataFor(e)
	if !ok {
		return nil, false
	}
	peer, ok := s.resolvePeer(e.PeerDstIP, e.PeerDstPort)
	if !ok {
		return nil, false
	}

	target := s.edges.targets.bound(peer.Service)
	targetNamespace := peer.Namespace
	if targetNamespace == "" || target != peer.Service {
		targetNamespace = "unknown"
	}

	return []string{
		meta.Namespace,
		meta.WorkloadName,
		targetNamespace,
		target,
	}, true
}

// recordEdgeL7 adds one L7 request to the topology families.
func (s *Sink) recordEdgeL7(e *events.Event, outcomeValue string, seconds float64) {
	identity, ok := s.edgeIdentity(e)
	if !ok {
		return
	}
	s.add(s.edges.requests, edgeRequestsTotal, appendLabels(identity, outcomeValue), 1)
	s.observe(s.edges.duration, edgeRequestDuration, identity, seconds)
}

// recordEdgeNetwork adds one network transfer to the topology, so the map
// covers flows carrying no L7 payload podtrace can decode.
func (s *Sink) recordEdgeNetwork(e *events.Event, direction string) {
	if e.Bytes == 0 {
		return
	}
	identity, ok := s.edgeIdentity(e)
	if !ok {
		return
	}
	s.add(s.edges.bytes, edgeBytesTotal, appendLabels(identity, direction), float64(e.Bytes))
}
