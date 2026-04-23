package agent

import (
	"testing"

	"github.com/podtrace/podtrace/internal/events"
)

func TestComputeNodeReport_DedupsCgroups(t *testing.T) {
	router := NewRouter(nil)
	exp := &recExp{name: "x"}
	router.Publish([]CRRule{
		mkRule("ns", "a", []uint64{1, 2}, []events.EventType{events.EventDNS}, exp),
		mkRule("ns", "b", []uint64{2, 3}, []events.EventType{events.EventDNS}, exp), // shares cgroup 2
	})
	router.Stats().incr(CRKey{"ns", "a"}, 10)
	router.Stats().incr(CRKey{"ns", "b"}, 5)

	rep := ComputeNodeReport("node-x", router, true)
	if rep.ActiveCgroups != 3 {
		t.Errorf("ActiveCgroups=%d want 3 (deduped)", rep.ActiveCgroups)
	}
	if rep.EventsTotal != 15 {
		t.Errorf("EventsTotal=%d want 15", rep.EventsTotal)
	}
	if !rep.Ready {
		t.Error("Ready=false, want true")
	}
}

// TestComputeNodeReport_EmptyRouterIsZeroed covers the no-CRs path:
// a freshly started agent has no rules, so every counter should be
// zero and Ready must reflect the callback's value.
func TestComputeNodeReport_EmptyRouterIsZeroed(t *testing.T) {
	router := NewRouter(nil)
	rep := ComputeNodeReport("node-x", router, false)
	if rep.ActiveCgroups != 0 || rep.EventsTotal != 0 || rep.DroppedEvents != 0 {
		t.Errorf("empty router not zero: %+v", rep)
	}
	if rep.Ready {
		t.Error("Ready=true despite callback returning false")
	}
	if rep.Node != "node-x" {
		t.Errorf("Node=%q want node-x", rep.Node)
	}
}