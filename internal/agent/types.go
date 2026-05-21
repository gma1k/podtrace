// Package agent implements the per-node DaemonSet runtime of podtrace.
//
// The agent watches PodTrace custom resources cluster-wide and the
// subset of Pods scheduled on its own node, resolves selectors into
// cgroup sets, and drives a single shared tracer across all active
// PodTrace CRs. Events produced by the tracer are routed to per-CR
// exporters according to each CR's cgroup membership and filter list.
package agent

import (
	"sync"
	"time"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/pkg/tracer"
)

type NodeName string

type CRKey struct {
	Namespace string
	Name      string
}

func (k CRKey) String() string { return k.Namespace + "/" + k.Name }

type CRRule struct {
	Key       CRKey
	CgroupIDs map[uint64]struct{} // kernel cgroup inode numbers the tracer will see on events
	Filters   map[events.EventType]struct{}
	Exporter  tracer.Exporter

	BundleRevision string

	// Policy is the resolved effective policy as read from the bundle.
	Policy PolicySnapshot

	MatchedPods int32

	Err error
}

// PolicySnapshot is the agent's view of the policy fields carried by a
// bundle.
type PolicySnapshot struct {
	EffectiveSamplePercent *int32

	Filters []string

	Thresholds *PolicyThresholds

	Hash string

	Generation int64
}

// PolicyThresholds is the agent-side counterpart of the bundle's
// Thresholds struct: same fields, same nil-means-unset semantics.
type PolicyThresholds struct {
	ErrorRatePercent *int32
	RTTSpikeMs       *int32
	FSSlowMs         *int32
}

// NodeReport aggregates the counters the status writer reports on one
// tick.
type NodeReport struct {
	Node           string
	Ready          bool
	ActiveCgroups  int32
	EventsTotal    int64
	DroppedEvents  int64
	LastHeartbeat  time.Time
	Message        string
}

// perCRStats tracks per-CR event counts for status reporting. Keyed by
// CRKey.
type perCRStats struct {
	mu     sync.Mutex
	counts map[CRKey]*crCounters
}

type crCounters struct {
	Events  int64
	Dropped int64
}

func newPerCRStats() *perCRStats {
	return &perCRStats{counts: map[CRKey]*crCounters{}}
}

// incr bumps the event count for a CR; creates the entry if absent.
func (s *perCRStats) incr(k CRKey, delta int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.counts[k]
	if c == nil {
		c = &crCounters{}
		s.counts[k] = c
	}
	c.Events += delta
}

// incrDropped bumps the drop count for a CR.
func (s *perCRStats) incrDropped(k CRKey, delta int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.counts[k]
	if c == nil {
		c = &crCounters{}
		s.counts[k] = c
	}
	c.Dropped += delta
}

// snapshot returns a copy of counts for every tracked CR.
func (s *perCRStats) snapshot() map[CRKey]crCounters {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[CRKey]crCounters, len(s.counts))
	for k, c := range s.counts {
		out[k] = *c
	}
	return out
}

// drop removes a CR's counters (called when a CR is deleted).
func (s *perCRStats) drop(k CRKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.counts, k)
}