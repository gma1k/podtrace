package tracer

import (
	"testing"
	"time"
)

func TestEvictQUICFlows_DropsStaleKeepsFresh(t *testing.T) {
	now := time.Now()
	flows := map[quicFlowKey]*quicFlowState{
		{cgroup: 1}: {lastSeen: now.Add(-2 * quicFlowTTL)},
		{cgroup: 2}: {lastSeen: now.Add(-1 * time.Second)},
	}
	evictQUICFlows(flows, now)
	if _, ok := flows[quicFlowKey{cgroup: 1}]; ok {
		t.Error("stale flow should have been evicted")
	}
	if _, ok := flows[quicFlowKey{cgroup: 2}]; !ok {
		t.Error("fresh in-progress flow must be retained")
	}
}

func TestEvictQUICFlows_NoWipeWhenAllFresh(t *testing.T) {
	now := time.Now()
	flows := make(map[quicFlowKey]*quicFlowState, quicMaxTrackedFlows)
	for i := 0; i < quicMaxTrackedFlows; i++ {
		flows[quicFlowKey{cgroup: uint64(i + 1)}] = &quicFlowState{
			lastSeen: now.Add(-time.Duration(quicMaxTrackedFlows-i) * time.Millisecond),
		}
	}
	evictQUICFlows(flows, now)
	if got := len(flows); got != quicMaxTrackedFlows-1 {
		t.Fatalf("expected exactly one eviction, len=%d want %d", got, quicMaxTrackedFlows-1)
	}
	if _, ok := flows[quicFlowKey{cgroup: 1}]; ok {
		t.Error("the least-recently-seen flow should have been evicted")
	}
}
