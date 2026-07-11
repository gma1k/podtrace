package kubernetes

import (
	"context"
	"sync"

	"github.com/podtrace/podtrace/pkg/tracer"
)

// TargetSource is a producer of PodInfo snapshots.
type TargetSource interface {
	Start(ctx context.Context) error
	Updates() <-chan []*PodInfo
	Snapshot() []*PodInfo
}

// Compile-time check that the existing registry satisfies the interface.
var _ TargetSource = (*TargetRegistry)(nil)

// ChannelTargetSource is a TargetSource whose snapshots are pushed in from
// the outside.
type ChannelTargetSource struct {
	updates chan []*PodInfo

	mu      sync.RWMutex
	latest  []*PodInfo
	started bool
	closed  bool
}

// NewChannelTargetSource constructs an idle source. Publish is a no-op
// until Start has been called.
func NewChannelTargetSource() *ChannelTargetSource {
	return &ChannelTargetSource{
		updates: make(chan []*PodInfo, 8),
	}
}

// Start marks the source as active and emits the current latest snapshot
// (which may be empty).
func (s *ChannelTargetSource) Start(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.started {
		return nil
	}
	s.started = true
	s.emitLocked(cloneForEmit(s.latest))
	return nil
}

// Updates returns a read-only channel of snapshots.
func (s *ChannelTargetSource) Updates() <-chan []*PodInfo {
	return s.updates
}

// Snapshot returns a defensive copy of the most recent snapshot.
func (s *ChannelTargetSource) Snapshot() []*PodInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneForEmit(s.latest)
}

// Publish replaces the current snapshot and emits it.
func (s *ChannelTargetSource) Publish(snapshot []*PodInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	cp := make([]*PodInfo, len(snapshot))
	copy(cp, snapshot)
	s.latest = cp
	if !s.started {
		return
	}
	s.emitLocked(cp)
}

// Close releases the internal channel.
func (s *ChannelTargetSource) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.started = false
	close(s.updates)
}

// emitLocked performs the non-blocking latest-wins send.
func (s *ChannelTargetSource) emitLocked(snap []*PodInfo) {
	select {
	case s.updates <- snap:
	default:
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
// consumed by pkg/tracer.Engine.
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
