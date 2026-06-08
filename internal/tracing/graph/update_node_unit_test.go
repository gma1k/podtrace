package graph

import (
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/diagnose/tracker"
)

func TestUpdateNode_MissingNodeIsNoOp(t *testing.T) {
	gb := NewGraphBuilder()
	gb.updateNode("missing", &tracker.Span{Duration: time.Second, Error: true})
	if _, ok := gb.nodes["missing"]; ok {
		t.Fatal("updateNode must not create a node for an unknown id")
	}
}

func TestUpdateNode_AccumulatesAndCountsErrors(t *testing.T) {
	gb := NewGraphBuilder()
	gb.nodes["svc"] = &Node{ID: "svc"}

	gb.updateNode("svc", &tracker.Span{Duration: 2 * time.Second, Error: false})
	gb.updateNode("svc", &tracker.Span{Duration: 3 * time.Second, Error: true})

	n := gb.nodes["svc"]
	if n.RequestCount != 2 {
		t.Errorf("RequestCount = %d, want 2", n.RequestCount)
	}
	if n.ErrorCount != 1 {
		t.Errorf("ErrorCount = %d, want 1", n.ErrorCount)
	}
	if n.TotalLatency != 5*time.Second {
		t.Errorf("TotalLatency = %v, want 5s", n.TotalLatency)
	}
}
