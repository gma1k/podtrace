package operator

import (
	"testing"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// TestFirstDegradedNode pins the rollup contract that turns one or more
// agent-reported per-node failures into a single ConditionDegraded
// message on the parent PodTrace. The rule: pick the lexicographically
// first failing node so the rolled-up message stays stable across
// reconciles when multiple nodes report errors at the same time.
func TestFirstDegradedNode(t *testing.T) {
	cases := []struct {
		name        string
		in          []podtracev1alpha1.PodTraceNodeStatus
		wantNode    string
		wantMessage string
		wantOK      bool
	}{
		{
			name:   "EmptyInputReturnsNotOK",
			in:     nil,
			wantOK: false,
		},
		{
			name: "OnlyHealthyRowsReturnsNotOK",
			in: []podtracev1alpha1.PodTraceNodeStatus{
				{Node: "a", Ready: true, Message: ""},
				{Node: "b", Ready: true, Message: "stale message that should be ignored"},
			},
			wantOK: false,
		},
		{
			name: "ReadyFalseWithoutMessageReturnsNotOK",
			in: []podtracev1alpha1.PodTraceNodeStatus{
				{Node: "a", Ready: false, Message: ""},
			},
			wantOK: false,
		},
		{
			name: "SingleDegradedRow",
			in: []podtracev1alpha1.PodTraceNodeStatus{
				{Node: "n1", Ready: false, Message: "build exporter: not yet implemented"},
			},
			wantNode:    "n1",
			wantMessage: "build exporter: not yet implemented",
			wantOK:      true,
		},
		{
			name: "PicksLexicographicallyFirstNode",
			in: []podtracev1alpha1.PodTraceNodeStatus{
				{Node: "zeta", Ready: false, Message: "z failed"},
				{Node: "alpha", Ready: false, Message: "a failed"},
				{Node: "mu", Ready: false, Message: "m failed"},
			},
			wantNode:    "alpha",
			wantMessage: "a failed",
			wantOK:      true,
		},
		{
			name: "MixHealthyAndDegraded",
			in: []podtracev1alpha1.PodTraceNodeStatus{
				{Node: "healthy-z", Ready: true},
				{Node: "broken-m", Ready: false, Message: "load bundle: timeout"},
				{Node: "healthy-a", Ready: true},
			},
			wantNode:    "broken-m",
			wantMessage: "load bundle: timeout",
			wantOK:      true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotNode, gotMsg, gotOK := firstDegradedNode(tc.in)
			if gotOK != tc.wantOK {
				t.Fatalf("ok = %v, want %v", gotOK, tc.wantOK)
			}
			if gotNode != tc.wantNode {
				t.Errorf("node = %q, want %q", gotNode, tc.wantNode)
			}
			if gotMsg != tc.wantMessage {
				t.Errorf("message = %q, want %q", gotMsg, tc.wantMessage)
			}
		})
	}
}