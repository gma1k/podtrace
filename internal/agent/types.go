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

// NodeName is supplied by the agent DaemonSet via the downward API
// ($NODE_NAME). It scopes every informer filter and every status patch.
// Kept as a package-level string rather than threaded everywhere
// because it is set once at process start and never changes.
type NodeName string

// CRKey uniquely identifies a PodTrace CR cluster-wide.
// (namespace, name) is guaranteed unique by the apiserver; we do not
// use UID because it is not stable across recreate-with-same-name and
// our router rules are keyed on user-facing identity.
type CRKey struct {
	Namespace string
	Name      string
}

func (k CRKey) String() string { return k.Namespace + "/" + k.Name }

// CRRule is the per-CR snapshot the router needs to route events.
// Assembled by the reconcile loop from matched pods + exporter bundles
// and handed to the router as a complete replacement each time
// anything under the CR changes. Immutable once published.
type CRRule struct {
	Key       CRKey
	CgroupIDs map[uint64]struct{}   // kernel cgroup inode numbers the tracer will see on events
	Filters   map[events.EventType]struct{}
	Exporter  tracer.Exporter

	// BundleRevision is the ResourceVersion of the exporter bundle
	// ConfigMap+Secret used to construct Exporter. Recorded so the
	// reconcile loop can detect credential rotation without recreating
	// an identical exporter.
	BundleRevision string

	// MatchedPods is the count of local pods currently satisfying the
	// CR's selector. Status writer reports this on status.nodeStatus.
	MatchedPods int32
}

// NodeReport aggregates the counters the status writer reports on one
// tick. Mirrors the fields of PodTraceNodeStatus so the writer can
// marshal it directly.
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
// CRKey. Shared between the router (writer) and status writer (reader).
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