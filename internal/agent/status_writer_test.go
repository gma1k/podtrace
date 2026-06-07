package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
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

// TestEmitOnce_HeartbeatFiresEveryTick pins the liveness wiring:
// every status-writer tick must call probes.
func TestEmitOnce_HeartbeatFiresEveryTick(t *testing.T) {
	router := NewRouter(nil)
	calls := 0
	w := &StatusWriter{
		Client:    nil,
		NodeName:  "node-x",
		Router:    router,
		Ready:     func() bool { return true },
		Heartbeat: func() { calls++ },
	}
	_ = w.emitOnce(context.Background())
	if calls != 1 {
		t.Errorf("Heartbeat call count = %d, want 1", calls)
	}
	_ = w.emitOnce(context.Background())
	if calls != 2 {
		t.Errorf("Heartbeat call count = %d, want 2", calls)
	}
}

func TestEmitOnce_NilHeartbeatIsSafe(t *testing.T) {
	router := NewRouter(nil)
	w := &StatusWriter{Router: router, NodeName: "node-x", Ready: func() bool { return true }}
	if err := w.emitOnce(context.Background()); err != nil {
		t.Fatalf("emitOnce with nil Heartbeat: %v", err)
	}
}

// TestBuildNodeStatusEntry covers the contract: how a CRRule
// — healthy, tombstoned, or running on an unready agent — gets
// rendered onto the PodTrace.status.nodeStatus row that the status
// writer patches. The apiserver round-trip is exercised by the
// envtest in reconciler_envtest_test.go.
func TestBuildNodeStatusEntry(t *testing.T) {
	const node = "node-x"
	now := time.Now()

	cases := []struct {
		name        string
		rule        *CRRule
		counters    crCounters
		agentReady  bool
		backendErr  error
		wantReady   bool
		wantMessage string
		wantReason  podtracev1alpha1.NodeStatusReason
		wantCgroups int32
		wantEvents  int64
		wantDropped int64
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
			wantReason:  podtracev1alpha1.NodeStatusReasonExporterBuildFailed,
			wantCgroups: 1,
		},
		{
			name: "HealthyRuleOnUnreadyAgent",
			rule: &CRRule{
				Key:       CRKey{"ns", "ok"},
				CgroupIDs: map[uint64]struct{}{1: {}},
				Exporter:  &recExp{},
			},
			counters:    crCounters{Events: 1},
			agentReady:  false,
			wantReady:   false,
			wantMessage: "agent not ready",
			wantReason:  podtracev1alpha1.NodeStatusReasonAgentUnready,
			wantEvents:  1,
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
			wantReason:  podtracev1alpha1.NodeStatusReasonBundleLoadFailed,
		},
		{
			// Backend failure (e.g. BPF/BTF unavailable) makes every
			// CR ready=false and surfaces a single "tracer backend
			// unavailable: …" message — operators see the root cause
			// instead of a confusing healthy-looking row with zero
			// events.
			name: "BackendErrOnHealthyRule",
			rule: &CRRule{
				Key:       CRKey{"ns", "ok"},
				CgroupIDs: map[uint64]struct{}{1: {}},
				Exporter:  &recExp{},
			},
			counters:    crCounters{},
			agentReady:  true,
			backendErr:  errors.New("BPF object not embedded in this build"),
			wantReady:   false,
			wantMessage: "tracer backend unavailable: BPF object not embedded in this build",
			wantReason:  podtracev1alpha1.NodeStatusReasonBackendUnavailable,
			wantCgroups: 1,
		},
		{
			// Backend failure takes precedence over per-CR rule errors.
			// rule.Err is the secondary effect; users should chase the
			// backend first.
			name: "BackendErrTakesPrecedenceOverRuleErr",
			rule: &CRRule{
				Key: CRKey{"ns", "tomb"},
				Err: errors.New("build exporter: zipkin not supported"),
			},
			counters:    crCounters{},
			agentReady:  true,
			backendErr:  errors.New("kernel missing CAP_BPF"),
			wantReady:   false,
			wantMessage: "tracer backend unavailable: kernel missing CAP_BPF",
			wantReason:  podtracev1alpha1.NodeStatusReasonBackendUnavailable,
		},
		{
			name: "PodMatchFailureReason",
			rule: &CRRule{
				Key: CRKey{"ns", "tomb"},
				Err: errors.New("match pods: invalid selector"),
			},
			agentReady:  true,
			wantReady:   false,
			wantMessage: "match pods: invalid selector",
			wantReason:  podtracev1alpha1.NodeStatusReasonPodMatchFailed,
		},
		{
			name: "CgroupResolutionFailureReason",
			rule: &CRRule{
				Key: CRKey{"ns", "tomb"},
				Err: errors.New("resolve cgroup IDs: kubepods missing"),
			},
			agentReady:  true,
			wantReady:   false,
			wantMessage: "resolve cgroup IDs: kubepods missing",
			wantReason:  podtracev1alpha1.NodeStatusReasonCgroupResolutionFailed,
		},
		{
			name: "UnclassifiedRuleErrFallsBackToUnknown",
			rule: &CRRule{
				Key: CRKey{"ns", "tomb"},
				Err: errors.New("something exotic happened"),
			},
			agentReady:  true,
			wantReady:   false,
			wantMessage: "something exotic happened",
			wantReason:  podtracev1alpha1.NodeStatusReasonUnknown,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildNodeStatusEntry(node, tc.rule, tc.counters, tc.agentReady, tc.backendErr, now)
			if got.Node != node {
				t.Errorf("Node = %q, want %q", got.Node, node)
			}
			if got.Ready != tc.wantReady {
				t.Errorf("Ready = %v, want %v", got.Ready, tc.wantReady)
			}
			if got.Message != tc.wantMessage {
				t.Errorf("Message = %q, want %q", got.Message, tc.wantMessage)
			}
			if got.Reason != tc.wantReason {
				t.Errorf("Reason = %q, want %q", got.Reason, tc.wantReason)
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

// TestBuildNodeStatusEntry_EchoesPolicyHash pins the agent → operator
// echo of policy_hash on every per-node status patch.
func TestBuildNodeStatusEntry_EchoesPolicyHash(t *testing.T) {
	rule := &CRRule{
		Key:       CRKey{Namespace: "ns", Name: "n"},
		CgroupIDs: map[uint64]struct{}{1: {}},
		Policy:    PolicySnapshot{Hash: "deadbeef"},
	}
	entry := buildNodeStatusEntry("node-x", rule, crCounters{}, true, nil, time.Now())
	if entry.PolicyHash != "deadbeef" {
		t.Errorf("PolicyHash = %q, want %q", entry.PolicyHash, "deadbeef")
	}
}