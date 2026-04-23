package kubernetes

import (
	"context"
	"sync"

	"github.com/podtrace/podtrace/pkg/tracer"
)

// TargetSource is a producer of PodInfo snapshots. It captures the contract
// shared by the existing TargetRegistry (informer-driven) and the
// ChannelTargetSource used by the CR-backed agent (pushed snapshots from a
// PodTrace reconciler on the agent side).
//
// The interface is intentionally identical to what callers of
// TargetRegistry already consume: Start kicks off production, Updates
// returns a read-only channel of full snapshots, Snapshot returns the
// latest known set without blocking. ChannelTargetSource is the seam
// CR-driven agents use when targets come from an external informer
// rather than the pod informer baked into TargetRegistry.
type TargetSource interface {
	Start(ctx context.Context) error
	Updates() <-chan []*PodInfo
	Snapshot() []*PodInfo
}

// Compile-time check that the existing registry satisfies the interface.
// This is the "source-agnostic" property in practice: any consumer of
// TargetRegistry can be rewritten against TargetSource without code change.
var _ TargetSource = (*TargetRegistry)(nil)

// ChannelTargetSource is a TargetSource whose snapshots are pushed in from
// the outside. The CR-driven agent will use this: its PodTrace informer
// merges all active CRs on the node into a single []*PodInfo and calls
// Publish once per merged state change.
//
// The implementation mirrors TargetRegistry.emitSnapshot's "keep latest,
// non-blocking" semantics so consumers see the newest state without the
// producer blocking on a slow consumer.
type ChannelTargetSource struct {
	updates chan []*PodInfo

	mu      sync.RWMutex
	latest  []*PodInfo
	started bool
}

// NewChannelTargetSource constructs an idle source. Publish is a no-op
// until Start has been called.
func NewChannelTargetSource() *ChannelTargetSource {
	return &ChannelTargetSource{
		updates: make(chan []*PodInfo, 8),
	}
}

// Start marks the source as active and emits the current latest snapshot
// (which may be empty). Start is idempotent.
func (s *ChannelTargetSource) Start(_ context.Context) error {
	s.mu.Lock()
	s.started = true
	latest := cloneForEmit(s.latest)
	s.mu.Unlock()
	s.emit(latest)
	return nil
}

// Updates returns a read-only channel of snapshots. Consumers should not
// retain the received slice beyond the loop iteration.
func (s *ChannelTargetSource) Updates() <-chan []*PodInfo {
	return s.updates
}

// Snapshot returns a defensive copy of the most recent snapshot.
func (s *ChannelTargetSource) Snapshot() []*PodInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneForEmit(s.latest)
}

// Publish replaces the current snapshot and emits it. Safe for concurrent
// use. If no consumer is reading, the oldest pending snapshot is dropped
// to make room for the newest (latest-wins semantics).
func (s *ChannelTargetSource) Publish(snapshot []*PodInfo) {
	s.mu.Lock()
	// Take a defensive copy so the producer can reuse its own slice.
	cp := make([]*PodInfo, len(snapshot))
	copy(cp, snapshot)
	s.latest = cp
	started := s.started
	s.mu.Unlock()

	if !started {
		return
	}
	s.emit(cp)
}

// Close releases the internal channel. Publish calls after Close panic.
func (s *ChannelTargetSource) Close() {
	s.mu.Lock()
	s.started = false
	s.mu.Unlock()
	close(s.updates)
}

func (s *ChannelTargetSource) emit(snap []*PodInfo) {
	select {
	case s.updates <- snap:
	default:
		// Keep latest without blocking: drop one pending, retry once.
		select {
		case <-s.updates:
		default:
		}
		select {
		case s.updates <- snap:
		default:
		}
	}
}

func cloneForEmit(in []*PodInfo) []*PodInfo {
	if in == nil {
		return nil
	}
	out := make([]*PodInfo, len(in))
	copy(out, in)
	return out
}

// ToTracerTargets converts a PodInfo snapshot into the tracer.TargetSet
// consumed by pkg/tracer.Engine. This is the sole shape-conversion point
// between the Kubernetes layer and the tracer engine; it lives here (not
// in pkg/tracer) to keep the engine free of Kubernetes imports.
func ToTracerTargets(in []*PodInfo) tracer.TargetSet {
	if len(in) == 0 {
		return nil
	}
	out := make(tracer.TargetSet, 0, len(in))
	for _, p := range in {
		if p == nil {
			continue
		}
		labels := make(map[string]string, len(p.Labels))
		for k, v := range p.Labels {
			labels[k] = v
		}
		out = append(out, tracer.Target{
			PodName:       p.PodName,
			Namespace:     p.Namespace,
			ContainerID:   p.ContainerID,
			ContainerName: p.ContainerName,
			CgroupPath:    p.CgroupPath,
			Labels:        labels,
			PodIP:         p.PodIP,
			OwnerKind:     p.OwnerKind,
			OwnerName:     p.OwnerName,
		})
	}
	return out
}
