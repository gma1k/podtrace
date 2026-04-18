package kubernetes

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/podtrace/podtrace/internal/config"
)

// TestCgroupRootCandidates_KubeletAbsPath covers the `filepath.IsAbs(kcp)` true
// branch and `full = kcp` in cgroupRootCandidates.
func TestCgroupRootCandidates_KubeletAbsPath(t *testing.T) {
	// Ensure the once has already fired (call detectKubeletCgroupParent once first
	// so the sync.Once is exhausted, then set kubeletCgroupParent directly).
	_ = detectKubeletCgroupParent()

	// Create a real temp dir to use as the absolute kubelet cgroup path.
	absDir := t.TempDir()

	// Directly set the cached value since Once has already run.
	origKCP := kubeletCgroupParent
	kubeletCgroupParent = absDir
	defer func() { kubeletCgroupParent = origKCP }()

	// Set a different base so absDir is not the base itself.
	origBase := config.CgroupBasePath
	baseDir := t.TempDir()
	config.SetCgroupBasePath(baseDir)
	defer config.SetCgroupBasePath(origBase)

	candidates := cgroupRootCandidates()

	found := false
	for _, c := range candidates {
		if c == absDir {
			found = true
		}
	}
	if !found {
		t.Errorf("expected absolute kubelet cgroup dir %q in candidates %v", absDir, candidates)
	}
}

// TestCgroupRootCandidates_KubeletRelPath covers the `full = filepath.Join(base, kcp)`
// branch (non-absolute kubelet cgroup path).
func TestCgroupRootCandidates_KubeletRelPath(t *testing.T) {
	// Ensure once has already fired.
	_ = detectKubeletCgroupParent()

	// Set up a base dir with a "kubepods" subdir.
	baseDir := t.TempDir()
	kubepods := filepath.Join(baseDir, "kubepods")
	if err := os.MkdirAll(kubepods, 0o755); err != nil {
		t.Fatal(err)
	}

	origBase := config.CgroupBasePath
	config.SetCgroupBasePath(baseDir)
	defer config.SetCgroupBasePath(origBase)

	// Set relative kubelet cgroup parent.
	origKCP := kubeletCgroupParent
	kubeletCgroupParent = "kubepods"
	defer func() { kubeletCgroupParent = origKCP }()

	candidates := cgroupRootCandidates()

	found := false
	for _, c := range candidates {
		if c == kubepods {
			found = true
		}
	}
	if !found {
		t.Errorf("expected kubepods dir %q in candidates %v", kubepods, candidates)
	}
}

// TestCgroupRootCandidates_KubeletPathNotExist covers the `dirExists(full)` false
// branch — kubelet cgroup dir set but doesn't exist on disk.
func TestCgroupRootCandidates_KubeletPathNotExist(t *testing.T) {
	_ = detectKubeletCgroupParent()

	baseDir := t.TempDir()
	origBase := config.CgroupBasePath
	config.SetCgroupBasePath(baseDir)
	defer config.SetCgroupBasePath(origBase)

	origKCP := kubeletCgroupParent
	kubeletCgroupParent = "/nonexistent/cgroup/path/that/does/not/exist"
	defer func() { kubeletCgroupParent = origKCP }()

	candidates := cgroupRootCandidates()

	for _, c := range candidates {
		if c == kubeletCgroupParent {
			t.Errorf("non-existent kubelet cgroup dir should NOT be in candidates, but got %v", candidates)
		}
	}
}
