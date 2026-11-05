package tracer

import (
	"testing"
	"time"
)

func TestQUICFlowsToTheSameServerAreSeparatedByLocalPort(t *testing.T) {
	now := time.Now()
	flows := map[quicFlowKey]*quicFlowState{}
	first := quicFlowFor(flows, quicFlowKey{cgroup: 1, port: 443, lport: 40001}, 1_000, now)
	first.done = true
	second := quicFlowFor(flows, quicFlowKey{cgroup: 1, port: 443, lport: 40002}, 2_000, now)
	if second == first || second.done {
		t.Fatal("a second connection to the same server must get its own reassembly state")
	}
}

func TestQUICFlowStartsOverOnceBPFRestartsTheBudget(t *testing.T) {
	now := time.Now()
	key := quicFlowKey{cgroup: 1, port: 443, lport: 40001}
	flows := map[quicFlowKey]*quicFlowState{}
	st := quicFlowFor(flows, key, 1_000, now)
	st.done = true
	st.pkts = [][]byte{{1}}

	if again := quicFlowFor(flows, key, 1_000+quicInitialWindowNs, now); !again.done {
		t.Fatal("packets inside the BPF window belong to the connection already reported")
	}
	reset := quicFlowFor(flows, key, 1_000+quicInitialWindowNs+1, now)
	if reset.done || len(reset.pkts) != 0 {
		t.Fatal("packets after the BPF window are a new connection on a reused flow key")
	}
	if reset.windowStart != 1_000+quicInitialWindowNs+1 {
		t.Fatalf("window must restart at the new packet, got %d", reset.windowStart)
	}
}

func TestQUICFlowTableMakesRoomForANewConnection(t *testing.T) {
	now := time.Now()
	flows := map[quicFlowKey]*quicFlowState{}
	for i := 0; i < quicMaxTrackedFlows; i++ {
		flows[quicFlowKey{cgroup: 1, lport: uint16(i)}] = &quicFlowState{lastSeen: now.Add(-quicFlowTTL - time.Second)}
	}
	key := quicFlowKey{cgroup: 2, port: 443, lport: 1}
	st := quicFlowFor(flows, key, 1_000, now)
	if flows[key] != st {
		t.Fatal("the new connection must be tracked")
	}
	if len(flows) != 1 {
		t.Fatalf("expired flows must be evicted when the table is full, %d left", len(flows))
	}
}

func TestQUICFlowIgnoresAnOlderStamp(t *testing.T) {
	now := time.Now()
	key := quicFlowKey{cgroup: 1, port: 443, lport: 40001}
	flows := map[quicFlowKey]*quicFlowState{}
	st := quicFlowFor(flows, key, 10_000_000_000, now)
	st.done = true
	if !quicFlowFor(flows, key, 5_000, now).done {
		t.Fatal("a record stamped before the window start must not wrap around into a reset")
	}
}
