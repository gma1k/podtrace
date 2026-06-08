package kubernetes

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/podtrace/podtrace/internal/config"
)

// withCgroupBase points config.CgroupBasePath at a fresh temp dir for the
// duration of the test, restoring the previous value on cleanup.
func withCgroupBase(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := config.CgroupBasePath
	config.SetCgroupBasePath(dir)
	t.Cleanup(func() { config.SetCgroupBasePath(orig) })
	return dir
}

// ─── statCgroupDirHasProcs ────────────────────────────────────────────────────

func TestStatCgroupDirHasProcs_OutsideBase(t *testing.T) {
	withCgroupBase(t)
	if statCgroupDirHasProcs("/some/other/place") {
		t.Error("expected false for path outside cgroup base")
	}
}

func TestStatCgroupDirHasProcs_DirMissing(t *testing.T) {
	base := withCgroupBase(t)
	if statCgroupDirHasProcs(filepath.Join(base, "does-not-exist")) {
		t.Error("expected false for missing cgroup dir")
	}
}

func TestStatCgroupDirHasProcs_NoProcsFile(t *testing.T) {
	base := withCgroupBase(t)
	dir := filepath.Join(base, "grp")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if statCgroupDirHasProcs(dir) {
		t.Error("expected false when cgroup.procs is absent")
	}
}

func TestStatCgroupDirHasProcs_HasProcsFile(t *testing.T) {
	base := withCgroupBase(t)
	dir := filepath.Join(base, "grp")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte("1\n"), 0o644); err != nil {
		t.Fatalf("write cgroup.procs: %v", err)
	}
	if !statCgroupDirHasProcs(dir) {
		t.Error("expected true when dir contains cgroup.procs")
	}
}

// ─── BuildPodInfoFromPreResolved: success path ────────────────────────────────

func TestBuildPodInfoFromPreResolved_Success(t *testing.T) {
	base := withCgroupBase(t)

	containerID := "abcdef1234567890"
	target := filepath.Join(base, "kubepods.slice", "pod_"+containerID)
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}

	info, err := BuildPodInfoFromPreResolved(PreResolvedRef{
		Namespace:     "ns",
		PodName:       "pod-a",
		ContainerID:   containerID,
		ContainerName: "app",
	})
	if err != nil {
		t.Fatalf("BuildPodInfoFromPreResolved: %v", err)
	}
	if info.PodName != "pod-a" || info.Namespace != "ns" {
		t.Errorf("unexpected metadata: %+v", info)
	}
	if info.ContainerID != containerID || info.ContainerName != "app" {
		t.Errorf("unexpected container fields: %+v", info)
	}
	if info.CgroupPath == "" {
		t.Error("expected resolved cgroup path to be populated")
	}
	if info.Labels == nil {
		t.Error("expected non-nil Labels map")
	}
}
