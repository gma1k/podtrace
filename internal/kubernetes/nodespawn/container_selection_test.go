package nodespawn

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	pkgkube "github.com/podtrace/podtrace/internal/kubernetes"
)

func multiContainerPod() *corev1.Pod {
	running := corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
		Spec:       corev1.PodSpec{NodeName: "node-1"},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "sidecar", ContainerID: "containerd://aaa", State: running},
				{Name: "app", ContainerID: "containerd://bbb", State: running},
			},
		},
	}
}

// TestResolveTargetNodes_HonorsContainerName is a regression test: the
// node-spawn path used to ignore --container entirely and embed the FIRST
// running container's ID into --preresolved-pod, so multi-container pods got
// the sidecar traced while argv showed the requested name.
func TestResolveTargetNodes_HonorsContainerName(t *testing.T) {
	cs := fake.NewSimpleClientset(multiContainerPod())

	got, err := ResolveTargetNodes(context.Background(), cs, pkgkube.TargetSelection{
		DefaultNamespace: "default",
		Pods:             []string{"web"},
		ContainerName:    "app",
	})
	if err != nil {
		t.Fatalf("ResolveTargetNodes: %v", err)
	}
	refs := got.ByNode["node-1"]
	if len(refs) != 1 {
		t.Fatalf("refs on node-1 = %d, want 1", len(refs))
	}
	if refs[0].ContainerName != "app" || refs[0].ContainerID != "bbb" {
		t.Errorf("resolved container = %s/%s, want app/bbb", refs[0].ContainerName, refs[0].ContainerID)
	}
}

func TestResolveTargetNodes_MissingContainerNameFails(t *testing.T) {
	cs := fake.NewSimpleClientset(multiContainerPod())

	_, err := ResolveTargetNodes(context.Background(), cs, pkgkube.TargetSelection{
		DefaultNamespace: "default",
		Pods:             []string{"web"},
		ContainerName:    "no-such-container",
	})
	if err == nil || !strings.Contains(err.Error(), "no-such-container") {
		t.Fatalf("expected a missing-container error, got %v", err)
	}
}

func TestPickRunningContainer_ByName(t *testing.T) {
	pod := multiContainerPod()
	if cs := pickRunningContainer(pod, "app"); cs == nil || cs.Name != "app" {
		t.Errorf("pickRunningContainer(pod, app) = %+v, want the app container", cs)
	}
	if cs := pickRunningContainer(pod, ""); cs == nil || cs.Name != "sidecar" {
		t.Errorf("pickRunningContainer(pod, \"\") = %+v, want first running (sidecar)", cs)
	}
	if cs := pickRunningContainer(pod, "ghost"); cs != nil {
		t.Errorf("pickRunningContainer(pod, ghost) = %+v, want nil", cs)
	}
}
