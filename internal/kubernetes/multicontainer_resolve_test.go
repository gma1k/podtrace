package kubernetes

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/podtrace/podtrace/internal/config"
)

func fakeCgroupBase(t *testing.T, containerIDs ...string) map[string]string {
	t.Helper()
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "cgroup.controllers"), []byte("cpu memory\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dirs := map[string]string{}
	for _, id := range containerIDs {
		d := filepath.Join(base, "kubepods.slice", "container-"+id)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "cgroup.procs"), []byte(""), 0o644); err != nil {
			t.Fatal(err)
		}
		dirs[id] = d
	}
	origBase := config.CgroupBasePath
	config.CgroupBasePath = base
	t.Setenv("PODTRACE_CRI_RESOLVE", "false")
	t.Cleanup(func() { config.CgroupBasePath = origBase })
	return dirs
}

func multiContainerRunningPod(ns, name string, containers map[string]string) *corev1.Pod {
	running := corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Status:     corev1.PodStatus{PodIP: "10.0.0.1"},
	}
	for _, cname := range []string{"sidecar", "app"} {
		id, ok := containers[cname]
		if !ok {
			continue
		}
		pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: cname})
		pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, corev1.ContainerStatus{
			Name: cname, ContainerID: "containerd://" + id, State: running,
		})
	}
	return pod
}

func TestResolvePod_MultiContainer(t *testing.T) {
	idSidecar := strings.Repeat("a", 64)
	idApp := strings.Repeat("b", 64)
	dirs := fakeCgroupBase(t, idSidecar, idApp)
	pod := multiContainerRunningPod("default", "web", map[string]string{"sidecar": idSidecar, "app": idApp})

	resolver := NewPodResolverForTesting(fake.NewSimpleClientset(pod))
	info, err := resolver.ResolvePod(context.Background(), "web", "default", "")
	if err != nil {
		t.Fatalf("ResolvePod: %v", err)
	}
	if len(info.Containers) != 2 {
		t.Fatalf("Containers = %d, want 2 (whole pod must be targeted)", len(info.Containers))
	}
	byName := map[string]ContainerTarget{}
	for _, c := range info.Containers {
		byName[c.Name] = c
	}
	if byName["sidecar"].ID != idSidecar || byName["sidecar"].CgroupPath != dirs[idSidecar] {
		t.Errorf("sidecar target = %+v, want id/cgroup resolved", byName["sidecar"])
	}
	if byName["app"].ID != idApp || byName["app"].CgroupPath != dirs[idApp] {
		t.Errorf("app target = %+v, want id/cgroup resolved", byName["app"])
	}
	if info.ContainerID != info.Containers[0].ID || info.CgroupPath != info.Containers[0].CgroupPath {
		t.Errorf("singular fields must mirror the first container entry")
	}
}

func TestResolvePod_NamedContainerNarrows(t *testing.T) {
	idSidecar := strings.Repeat("c", 64)
	idApp := strings.Repeat("d", 64)
	fakeCgroupBase(t, idSidecar, idApp)
	pod := multiContainerRunningPod("default", "web", map[string]string{"sidecar": idSidecar, "app": idApp})

	resolver := NewPodResolverForTesting(fake.NewSimpleClientset(pod))
	info, err := resolver.ResolvePod(context.Background(), "web", "default", "app")
	if err != nil {
		t.Fatalf("ResolvePod: %v", err)
	}
	if len(info.Containers) != 1 || info.Containers[0].Name != "app" || info.Containers[0].ID != idApp {
		t.Fatalf("Containers = %+v, want exactly the app container", info.Containers)
	}
}

func TestResolvePod_PartialCgroupFailure(t *testing.T) {
	idSidecar := strings.Repeat("e", 64)
	idApp := strings.Repeat("f", 64)
	fakeCgroupBase(t, idApp) // sidecar's cgroup deliberately absent
	pod := multiContainerRunningPod("default", "web", map[string]string{"sidecar": idSidecar, "app": idApp})

	resolver := NewPodResolverForTesting(fake.NewSimpleClientset(pod))
	info, err := resolver.ResolvePod(context.Background(), "web", "default", "")
	if err != nil {
		t.Fatalf("ResolvePod: %v", err)
	}
	if len(info.Containers) != 1 || info.Containers[0].Name != "app" {
		t.Fatalf("Containers = %+v, want the resolvable app container only", info.Containers)
	}
}

func TestResolvePodInfoFromObject_MultiContainer(t *testing.T) {
	idSidecar := strings.Repeat("1", 64)
	idApp := strings.Repeat("2", 64)
	fakeCgroupBase(t, idSidecar, idApp)
	pod := multiContainerRunningPod("prod", "api-0", map[string]string{"sidecar": idSidecar, "app": idApp})

	info, err := resolvePodInfoFromObject(context.Background(), pod, "")
	if err != nil {
		t.Fatalf("resolvePodInfoFromObject: %v", err)
	}
	if len(info.Containers) != 2 {
		t.Fatalf("Containers = %d, want 2", len(info.Containers))
	}
}
