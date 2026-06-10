package nodespawn

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	pkgkube "github.com/podtrace/podtrace/internal/kubernetes"
)

func pod(ns, name, node string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: labels},
		Spec:       corev1.PodSpec{NodeName: node},
	}
}

func TestResolveTargetNodes_NilClientset(t *testing.T) {
	if _, err := ResolveTargetNodes(context.Background(), nil, pkgkube.TargetSelection{}); err == nil {
		t.Fatalf("expected error for nil clientset")
	}
}

func TestResolveTargetNodes_ExplicitPods_FanOutByNode(t *testing.T) {
	cs := fake.NewClientset(
		pod("ns1", "a", "node-1", nil),
		pod("ns1", "b", "node-2", nil),
		pod("ns2", "c", "node-1", nil),
	)
	sel := pkgkube.TargetSelection{
		DefaultNamespace: "ns1",
		Pods:             []string{"a", "b", "ns2/c"},
	}

	got, err := ResolveTargetNodes(context.Background(), cs, sel)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got.NodeNames, []string{"node-1", "node-2"}) {
		t.Errorf("node names = %v, want [node-1 node-2]", got.NodeNames)
	}
	wantNode1 := []PodRef{{Namespace: "ns1", Name: "a"}, {Namespace: "ns2", Name: "c"}}
	if !reflect.DeepEqual(got.ByNode["node-1"], wantNode1) {
		t.Errorf("node-1 refs = %v, want %v", got.ByNode["node-1"], wantNode1)
	}
	wantNode2 := []PodRef{{Namespace: "ns1", Name: "b"}}
	if !reflect.DeepEqual(got.ByNode["node-2"], wantNode2) {
		t.Errorf("node-2 refs = %v, want %v", got.ByNode["node-2"], wantNode2)
	}
}

func TestResolveTargetNodes_PodSelector_AcrossNamespaces(t *testing.T) {
	cs := fake.NewClientset(
		pod("app", "api-1", "node-1", map[string]string{"app": "api"}),
		pod("app", "api-2", "node-2", map[string]string{"app": "api"}),
		pod("app", "worker", "node-1", map[string]string{"app": "worker"}),
		pod("other", "api-3", "node-1", map[string]string{"app": "api"}),
	)
	sel := pkgkube.TargetSelection{
		Namespaces:  []string{"app", "other"},
		PodSelector: "app=api",
	}
	got, err := ResolveTargetNodes(context.Background(), cs, sel)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got.NodeNames, []string{"node-1", "node-2"}) {
		t.Errorf("node names = %v, want [node-1 node-2]", got.NodeNames)
	}
	got1 := got.ByNode["node-1"]
	want1 := []PodRef{{Namespace: "app", Name: "api-1"}, {Namespace: "other", Name: "api-3"}}
	if !reflect.DeepEqual(got1, want1) {
		t.Errorf("node-1 refs = %v, want %v", got1, want1)
	}
	got2 := got.ByNode["node-2"]
	want2 := []PodRef{{Namespace: "app", Name: "api-2"}}
	if !reflect.DeepEqual(got2, want2) {
		t.Errorf("node-2 refs = %v, want %v", got2, want2)
	}
}

func TestResolveTargetNodes_AllInNamespace(t *testing.T) {
	cs := fake.NewClientset(
		pod("ns1", "p1", "node-1", nil),
		pod("ns1", "p2", "node-2", nil),
		pod("ns2", "ignored", "node-1", nil),
	)
	sel := pkgkube.TargetSelection{
		DefaultNamespace: "ns1",
		AllInNamespace:   true,
	}
	got, err := ResolveTargetNodes(context.Background(), cs, sel)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got.NodeNames, []string{"node-1", "node-2"}) {
		t.Errorf("node names = %v, want [node-1 node-2]", got.NodeNames)
	}
	if got.ByNode["node-1"][0].Name != "p1" || got.ByNode["node-2"][0].Name != "p2" {
		t.Errorf("unexpected refs: %+v", got.ByNode)
	}
}

func TestResolveTargetNodes_SkipsTerminatingPods(t *testing.T) {
	terminating := pod("ns1", "going", "node-1", map[string]string{"app": "x"})
	now := metav1.NewTime(time.Now())
	terminating.DeletionTimestamp = &now
	cs := fake.NewClientset(
		terminating,
		pod("ns1", "alive", "node-1", map[string]string{"app": "x"}),
	)
	sel := pkgkube.TargetSelection{
		DefaultNamespace: "ns1",
		AllInNamespace:   true,
	}
	got, err := ResolveTargetNodes(context.Background(), cs, sel)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.ByNode["node-1"]) != 1 || got.ByNode["node-1"][0].Name != "alive" {
		t.Errorf("expected only the non-terminating pod, got %+v", got.ByNode["node-1"])
	}
}

func TestResolveTargetNodes_AllUnscheduled_Errors(t *testing.T) {
	cs := fake.NewClientset(
		pod("ns1", "pending", "", nil),
	)
	sel := pkgkube.TargetSelection{
		DefaultNamespace: "ns1",
		Pods:             []string{"pending"},
	}
	_, err := ResolveTargetNodes(context.Background(), cs, sel)
	if err == nil {
		t.Fatalf("expected error when all pods unscheduled")
	}
	if !strings.Contains(err.Error(), "not yet scheduled") {
		t.Errorf("error %q does not mention scheduling state", err)
	}
}

func TestResolveTargetNodes_GetPodError_Propagates(t *testing.T) {
	cs := fake.NewClientset() // no pods
	sel := pkgkube.TargetSelection{
		DefaultNamespace: "ns1",
		Pods:             []string{"missing"},
	}
	_, err := ResolveTargetNodes(context.Background(), cs, sel)
	if err == nil {
		t.Fatalf("expected error from missing pod")
	}
}

// podWithContainer constructs a pod whose first container is in the given
// state — used by the pickRunningContainer tests to pin the selection logic
// for stale-restart / crash-loop / just-starting scenarios.
func podWithContainer(ns, name, node, cName, cID string, state corev1.ContainerState) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:        cName,
				ContainerID: cID,
				State:       state,
			}},
		},
	}
}

func TestPickRunningContainer_PrefersRunning(t *testing.T) {
	p := &corev1.Pod{Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
		{Name: "a", ContainerID: "containerd://aaa", State: corev1.ContainerState{
			Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"},
		}},
		{Name: "b", ContainerID: "containerd://bbb", State: corev1.ContainerState{
			Running: &corev1.ContainerStateRunning{},
		}},
		{Name: "c", ContainerID: "containerd://ccc", State: corev1.ContainerState{
			Terminated: &corev1.ContainerStateTerminated{ExitCode: 0},
		}},
	}}}
	cs := pickRunningContainer(p, "")
	if cs == nil || cs.Name != "b" {
		t.Fatalf("expected to pick the Running container, got %+v", cs)
	}
}

func TestPickRunningContainer_RejectsAllNonRunning(t *testing.T) {
	cases := map[string]corev1.ContainerState{
		"Waiting":    {Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}},
		"Terminated": {Terminated: &corev1.ContainerStateTerminated{ExitCode: 1, Reason: "Error"}},
	}
	for name, st := range cases {
		t.Run(name, func(t *testing.T) {
			p := &corev1.Pod{Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
				{Name: "x", ContainerID: "containerd://xxx", State: st},
			}}}
			if cs := pickRunningContainer(p, ""); cs != nil {
				t.Errorf("must not pick a %s container, got %+v", name, cs)
			}
		})
	}
}

func TestPickRunningContainer_RejectsRunningWithEmptyID(t *testing.T) {
	// A Pod can momentarily be in Status.Running with ContainerID="" right
	// at startup. We must NOT hand the spawn pod an empty containerID.
	p := &corev1.Pod{Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
		{Name: "x", ContainerID: "", State: corev1.ContainerState{
			Running: &corev1.ContainerStateRunning{},
		}},
	}}}
	if cs := pickRunningContainer(p, ""); cs != nil {
		t.Errorf("Running container with empty ID must be rejected, got %+v", cs)
	}
}

// TestResolveTargetNodes_SkipsNonRunningContainerIDs — the fix for the
// cross-node "cgroup path not found" failure mode: when one matching pod's
// container is Waiting/Terminated, the workstation must NOT hand its stale
// containerID to the spawn pod. The pod is still routed to its node (with
// an empty ContainerID), and main.go's preresolved loop skips it cleanly.
func TestResolveTargetNodes_SkipsNonRunningContainerIDs(t *testing.T) {
	running := podWithContainer("ns", "alive", "node-1", "app",
		"containerd://aaaaaa", corev1.ContainerState{
			Running: &corev1.ContainerStateRunning{},
		})
	restarting := podWithContainer("ns", "restarting", "node-1", "app",
		"containerd://bbbbbb", corev1.ContainerState{
			Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"},
		})
	cs := fake.NewClientset(running, restarting)

	sel := pkgkube.TargetSelection{
		DefaultNamespace: "ns",
		Pods:             []string{"alive", "restarting"},
	}
	out, err := ResolveTargetNodes(context.Background(), cs, sel)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if got := len(out.ByNode["node-1"]); got != 2 {
		t.Fatalf("expected both pods routed to node-1, got %d", got)
	}
	var aliveID, restartingID string
	for _, r := range out.ByNode["node-1"] {
		switch r.Name {
		case "alive":
			aliveID = r.ContainerID
		case "restarting":
			restartingID = r.ContainerID
		}
	}
	if aliveID != "aaaaaa" {
		t.Errorf("Running pod must propagate containerID, got %q", aliveID)
	}
	if restartingID != "" {
		t.Errorf("CrashLoopBackOff pod must NOT propagate a stale containerID, got %q", restartingID)
	}
}
