package kubernetes

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
)

func TestCgroupRootCandidates_KubeletAbsPath(t *testing.T) {
	_ = detectKubeletCgroupParent()

	origBase := config.CgroupBasePath
	baseDir := t.TempDir()
	config.SetCgroupBasePath(baseDir)
	defer config.SetCgroupBasePath(origBase)

	origKCP := kubeletCgroupParent
	defer func() { kubeletCgroupParent = origKCP }()

	outOfBase := t.TempDir()
	kubeletCgroupParent = outOfBase
	for _, c := range cgroupRootCandidates() {
		if c == outOfBase {
			t.Errorf("out-of-base kubelet cgroup dir %q must not be admitted", outOfBase)
		}
	}

	inBase := filepath.Join(baseDir, "kubepods")
	if err := os.MkdirAll(inBase, 0o755); err != nil {
		t.Fatal(err)
	}
	kubeletCgroupParent = inBase
	found := false
	for _, c := range cgroupRootCandidates() {
		if c == inBase {
			found = true
		}
	}
	if !found {
		t.Errorf("in-base kubelet cgroup dir %q should be admitted", inBase)
	}
}

func TestCgroupRootCandidates_KubeletRelPath(t *testing.T) {
	_ = detectKubeletCgroupParent()

	baseDir := t.TempDir()
	kubepods := filepath.Join(baseDir, "kubepods")
	if err := os.MkdirAll(kubepods, 0o755); err != nil {
		t.Fatal(err)
	}

	origBase := config.CgroupBasePath
	config.SetCgroupBasePath(baseDir)
	defer config.SetCgroupBasePath(origBase)

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
