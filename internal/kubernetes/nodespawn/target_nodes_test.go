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
