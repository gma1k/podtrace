package operator

import (
	"context"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func TestMergeSessionJobRefs_CarriesForwardGCdNode(t *testing.T) {
	prior := []podtracev1alpha1.SessionJobRef{
		{Node: "node-a", Name: "pts-a", Completed: true},
	}
	live := []batchv1.Job{{
		ObjectMeta: metav1.ObjectMeta{Name: "pts-b", Labels: map[string]string{LabelNodeName: "node-b"}},
		Status:     batchv1.JobStatus{Active: 1},
	}}
	merged := mergeSessionJobRefs(live, prior)
	byNode := map[string]podtracev1alpha1.SessionJobRef{}
	for _, r := range merged {
		byNode[r.Node] = r
	}
	if _, ok := byNode["node-a"]; !ok {
		t.Fatalf("completed GC'd node-a dropped from merged refs: %+v", merged)
	}
	if !byNode["node-a"].Completed {
		t.Errorf("carried-forward node-a must stay Completed")
	}
	if byNode["node-b"].Completed {
		t.Errorf("running node-b must not be Completed")
	}
}

func TestComputeSessionState_CompletesViaCarriedRefs(t *testing.T) {
	refsRunning := []podtracev1alpha1.SessionJobRef{
		{Node: "node-a", Completed: true},
		{Node: "node-b", Completed: false},
	}
	liveRunning := []batchv1.Job{{Status: batchv1.JobStatus{Active: 1}}}
	if got := computeSessionState(refsRunning, liveRunning, 2); got != podtracev1alpha1.SessionStateRunning {
		t.Errorf("with one node still running, want Running, got %s", got)
	}

	refsDone := []podtracev1alpha1.SessionJobRef{
		{Node: "node-a", Completed: true},
		{Node: "node-b", Completed: true},
	}
	if got := computeSessionState(refsDone, nil, 2); got != podtracev1alpha1.SessionStateCompleted {
		t.Errorf("both nodes completed (node-a carried), want Completed, got %s", got)
	}

	refsFailed := []podtracev1alpha1.SessionJobRef{
		{Node: "node-a", Completed: true, Message: sessionJobFailedMessage},
		{Node: "node-b", Completed: true},
	}
	if got := computeSessionState(refsFailed, nil, 2); got != podtracev1alpha1.SessionStateFailed {
		t.Errorf("a failed node must yield Failed, got %s", got)
	}
}

func TestEnsureJobs_SkipsCompletedNode(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "diag", Namespace: "team-a", UID: "u-skip-000"},
		Spec:       podtracev1alpha1.PodTraceSessionSpec{Duration: metav1.Duration{Duration: 1e9}},
	}
	targets := sessionTargets{Nodes: []string{"node-a", "node-b"}}
	completed := map[string]struct{}{"node-a": {}}

	if _, err := r.ensureJobs(context.Background(), s, nil, targets, completed); err != nil {
		t.Fatalf("ensureJobs: %v", err)
	}

	var jobs batchv1.JobList
	if err := c.List(context.Background(), &jobs, client.InNamespace("podtrace-system")); err != nil {
		t.Fatal(err)
	}
	nodes := map[string]bool{}
	for i := range jobs.Items {
		nodes[jobs.Items[i].Labels[LabelNodeName]] = true
	}
	if nodes["node-a"] {
		t.Error("node-a Job was (re)created despite being recorded complete — duplicate capture")
	}
	if !nodes["node-b"] {
		t.Error("node-b Job should have been created")
	}
}
