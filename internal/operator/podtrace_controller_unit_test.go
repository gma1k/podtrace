package operator

import (
	"testing"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// TestFirstDegradedNode pins the rollup contract that turns one or more
// agent-reported per-node failures into a single ConditionDegraded
// message on the parent PodTrace.
func TestFirstDegradedNode(t *testing.T) {
	cases := []struct {
		name        string
		in          []podtracev1alpha1.PodTraceNodeStatus
		wantNode    string
		wantMessage string
		wantReason  podtracev1alpha1.NodeStatusReason
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
				{Node: "n1", Ready: false, Message: "build exporter: not yet implemented",
					Reason: podtracev1alpha1.NodeStatusReasonExporterBuildFailed},
			},
			wantNode:    "n1",
			wantMessage: "build exporter: not yet implemented",
			wantReason:  podtracev1alpha1.NodeStatusReasonExporterBuildFailed,
			wantOK:      true,
		},
		{
			name: "PicksLexicographicallyFirstNode",
			in: []podtracev1alpha1.PodTraceNodeStatus{
				{Node: "zeta", Ready: false, Message: "z failed",
					Reason: podtracev1alpha1.NodeStatusReasonUnknown},
				{Node: "alpha", Ready: false, Message: "a failed",
					Reason: podtracev1alpha1.NodeStatusReasonBundleLoadFailed},
				{Node: "mu", Ready: false, Message: "m failed",
					Reason: podtracev1alpha1.NodeStatusReasonExporterBuildFailed},
			},
			wantNode:    "alpha",
			wantMessage: "a failed",
			wantReason:  podtracev1alpha1.NodeStatusReasonBundleLoadFailed,
			wantOK:      true,
		},
		{
			name: "MixHealthyAndDegraded",
			in: []podtracev1alpha1.PodTraceNodeStatus{
				{Node: "healthy-z", Ready: true},
				{Node: "broken-m", Ready: false, Message: "load bundle: timeout",
					Reason: podtracev1alpha1.NodeStatusReasonBundleLoadFailed},
				{Node: "healthy-a", Ready: true},
			},
			wantNode:    "broken-m",
			wantMessage: "load bundle: timeout",
			wantReason:  podtracev1alpha1.NodeStatusReasonBundleLoadFailed,
			wantOK:      true,
		},
		{
			name: "EmptyReasonAccepted",
			in: []podtracev1alpha1.PodTraceNodeStatus{
				{Node: "n1", Ready: false, Message: "legacy agent didn't set reason"},
			},
			wantNode:    "n1",
			wantMessage: "legacy agent didn't set reason",
			wantReason:  "",
			wantOK:      true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotNode, gotMsg, gotReason, gotOK := firstDegradedNode(tc.in)
			if gotOK != tc.wantOK {
				t.Fatalf("ok = %v, want %v", gotOK, tc.wantOK)
			}
			if gotNode != tc.wantNode {
				t.Errorf("node = %q, want %q", gotNode, tc.wantNode)
			}
			if gotMsg != tc.wantMessage {
				t.Errorf("message = %q, want %q", gotMsg, tc.wantMessage)
			}
			if gotReason != tc.wantReason {
				t.Errorf("reason = %q, want %q", gotReason, tc.wantReason)
			}
		})
	}
}
