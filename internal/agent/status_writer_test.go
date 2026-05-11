package agent

import (
	"errors"
	"testing"
	"time"

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

// TestBuildNodeStatusEntry covers the Phase 0 contract: how a CRRule
// — healthy, tombstoned, or running on an unready agent — gets
// rendered onto the PodTrace.status.nodeStatus row that the status
// writer patches. The apiserver round-trip is exercised by the
// envtest in reconciler_envtest_test.go.
func TestBuildNodeStatusEntry(t *testing.T) {
	const node = "node-x"
	now := time.Now()

	cases := []struct {
		name          string
		rule          *CRRule
		counters      crCounters
		agentReady    bool
		wantReady     bool
		wantMessage   string
		wantCgroups   int32
		wantEvents    int64
		wantDropped   int64
	}{
		{
			name: "HealthyRule",
			rule: &CRRule{
				Key:       CRKey{"ns", "ok"},
				CgroupIDs: map[uint64]struct{}{1: {}, 2: {}},
				Exporter:  &recExp{},
			},
			counters:    crCounters{Events: 7, Dropped: 3},
			agentReady:  true,
			wantReady:   true,
			wantCgroups: 2,
			wantEvents:  7,
			wantDropped: 3,
		},
		{
			name: "TombstoneOnHealthyAgent",
			rule: &CRRule{
				Key:       CRKey{"ns", "tomb"},
				CgroupIDs: map[uint64]struct{}{42: {}},
				Err:       errors.New("build exporter: not yet implemented in agent mode"),
			},
			counters:    crCounters{},
			agentReady:  true,
			wantReady:   false,
			wantMessage: "build exporter: not yet implemented in agent mode",
			wantCgroups: 1,
		},
		{
			name: "HealthyRuleOnUnreadyAgent",
			rule: &CRRule{
				Key:       CRKey{"ns", "ok"},
				CgroupIDs: map[uint64]struct{}{1: {}},
				Exporter:  &recExp{},
			},
			counters:   crCounters{Events: 1},
			agentReady: false,
			wantReady:  false,
			wantEvents: 1,
			wantCgroups: 1,
		},
		{
			name: "TombstoneOnUnreadyAgent",
			rule: &CRRule{
				Key: CRKey{"ns", "tomb"},
				Err: errors.New("load bundle: parse error"),
			},
			counters:    crCounters{},
			agentReady:  false,
			wantReady:   false,
			wantMessage: "load bundle: parse error",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildNodeStatusEntry(node, tc.rule, tc.counters, tc.agentReady, now)
			if got.Node != node {
				t.Errorf("Node = %q, want %q", got.Node, node)
			}
			if got.Ready != tc.wantReady {
				t.Errorf("Ready = %v, want %v", got.Ready, tc.wantReady)
			}
			if got.Message != tc.wantMessage {
				t.Errorf("Message = %q, want %q", got.Message, tc.wantMessage)
			}
			if got.ActiveCgroups != tc.wantCgroups {
				t.Errorf("ActiveCgroups = %d, want %d", got.ActiveCgroups, tc.wantCgroups)
			}
			if got.EventsTotal != tc.wantEvents {
				t.Errorf("EventsTotal = %d, want %d", got.EventsTotal, tc.wantEvents)
			}
			if got.DroppedEvents != tc.wantDropped {
				t.Errorf("DroppedEvents = %d, want %d", got.DroppedEvents, tc.wantDropped)
			}
			if got.LastHeartbeat.Time.IsZero() {
				t.Error("LastHeartbeat must be set")
			}
		})
	}
}