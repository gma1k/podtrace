package kubernetes

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
)

func TestFindCgroupPathV2_ResolvesSystemdNestedContainer(t *testing.T) {
	origBase := config.CgroupBasePath
	base := t.TempDir()
	config.SetCgroupBasePath(base)
	defer config.SetCgroupBasePath(origBase)

	cid := "3efb8417ec5becbd398719f2fbedc3bb13c6c121abeb4909b6a6842439634041"
	scope := filepath.Join(base,
		"kubelet.slice",
		"kubelet-kubepods.slice",
		"kubelet-kubepods-besteffort.slice",
		"kubelet-kubepods-besteffort-pod11111111_2222_3333_4444_555555555555.slice",
		"cri-containerd-"+cid+".scope",
	)
	if err := os.MkdirAll(scope, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scope, "cgroup.procs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := findCgroupPathV2(cid)
	if err != nil {
		t.Fatalf("findCgroupPathV2: %v", err)
	}
	if got != scope {
		t.Fatalf("resolved %q, want %q", got, scope)
	}
}

func TestFindCgroupPathV2_DepthBoundStopsDeepWalk(t *testing.T) {
	origBase := config.CgroupBasePath
	base := t.TempDir()
	config.SetCgroupBasePath(base)
	defer config.SetCgroupBasePath(origBase)

	cid := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbef0"
	parts := []string{base}
	for i := 0; i < maxCgroupWalkDepth+2; i++ {
		parts = append(parts, "kubelet.slice")
	}
	deep := filepath.Join(append(parts, "cri-containerd-"+cid+".scope")...)
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "cgroup.procs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := findCgroupPathV2(cid); err == nil {
		t.Fatal("expected depth-bounded walk to miss a cgroup nested beyond the cap")
	}
}
