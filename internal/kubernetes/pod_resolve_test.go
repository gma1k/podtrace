package kubernetes

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/podtrace/podtrace/internal/config"
)

func TestResolvePod_SuccessWithLabelsAndOwner(t *testing.T) {
	cid := hex64()
	wantCgroup := newCgroupV2Sandbox(t, cid)

	pod := runningPod("uid-rp", "prod", "api-0", "app", cid)
	clientset := fake.NewSimpleClientset(pod)
	resolver := NewPodResolverForTesting(clientset)

	info, err := resolver.ResolvePod(context.Background(), "api-0", "prod", "")
	if err != nil {
		t.Fatalf("ResolvePod: %v", err)
	}
	if info.Labels["app"] != "demo" {
		t.Errorf("expected label app=demo, got %v", info.Labels)
	}
	if info.OwnerKind != "ReplicaSet" || info.OwnerName != "api-0-rs" {
		t.Errorf("owner: got %q/%q want ReplicaSet/api-0-rs", info.OwnerKind, info.OwnerName)
	}
	if info.CgroupPath != wantCgroup {
		t.Errorf("cgroup: got %q want %q", info.CgroupPath, wantCgroup)
	}
}

func TestBuildPodInfoFromPreResolved_ValidIDNotFound(t *testing.T) {
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "cgroup.controllers"), []byte("cpu\n"), 0o644); err != nil {
		t.Fatalf("write cgroup.controllers: %v", err)
	}
	origBase := config.CgroupBasePath
	config.SetCgroupBasePath(base)
	t.Cleanup(func() { config.SetCgroupBasePath(origBase) })

	origProc := config.ProcBasePath
	config.SetProcBasePath(t.TempDir())
	t.Cleanup(func() { config.SetProcBasePath(origProc) })

	_, err := BuildPodInfoFromPreResolved(PreResolvedRef{
		Namespace: "ns", PodName: "p", ContainerID: hex64(), ContainerName: "app",
	})
	if err == nil {
		t.Fatal("expected a cgroup-not-found error for an unresolvable container ID")
	}
}

func TestCgroupV1ControllerRoots(t *testing.T) {
	orig := config.CgroupBasePath
	t.Cleanup(func() { config.SetCgroupBasePath(orig) })

	v2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(v2, "cgroup.controllers"), []byte("cpu\n"), 0o644); err != nil {
		t.Fatalf("write cgroup.controllers: %v", err)
	}
	config.SetCgroupBasePath(v2)
	if got := cgroupV1ControllerRoots(); got != nil {
		t.Errorf("expected nil for a cgroup-v2 base, got %v", got)
	}

	config.SetCgroupBasePath(filepath.Join(t.TempDir(), "does-not-exist"))
	if got := cgroupV1ControllerRoots(); got != nil {
		t.Errorf("expected nil for a missing base, got %v", got)
	}

	v1 := t.TempDir()
	if err := os.MkdirAll(filepath.Join(v1, "cpu"), 0o755); err != nil {
		t.Fatalf("mkdir controller: %v", err)
	}
	if err := os.WriteFile(filepath.Join(v1, "notes.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	config.SetCgroupBasePath(v1)
	roots := cgroupV1ControllerRoots()
	if len(roots) != 1 || !strings.HasSuffix(roots[0], string(os.PathSeparator)+"cpu") {
		t.Errorf("expected only the cpu controller dir, got %v", roots)
	}
}

func TestNamespaceFromKubeconfig(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "config")
	content := `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://example:6443
  name: c
contexts:
- context:
    cluster: c
    namespace: my-namespace
    user: u
  name: ctx
current-context: ctx
users:
- name: u
  user: {}
`
	if err := os.WriteFile(good, []byte(content), 0o644); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	ns, ok := NamespaceFromKubeconfig(good)
	if !ok || ns != "my-namespace" {
		t.Errorf("NamespaceFromKubeconfig(good) = (%q, %v), want (my-namespace, true)", ns, ok)
	}

	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("\tnot: [valid: yaml"), 0o644); err != nil {
		t.Fatalf("write bad kubeconfig: %v", err)
	}
	if ns, ok := NamespaceFromKubeconfig(bad); ok || ns != "" {
		t.Errorf("NamespaceFromKubeconfig(bad) = (%q, %v), want (\"\", false)", ns, ok)
	}
}
