package kubernetes

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStatCgroupDir_OutsideBase(t *testing.T) {
	withCgroupBase(t)
	if statCgroupDir("/some/other/place") {
		t.Error("expected false for path outside cgroup base")
	}
}

func TestStatCgroupDir_DirMissing(t *testing.T) {
	base := withCgroupBase(t)
	if statCgroupDir(filepath.Join(base, "does-not-exist")) {
		t.Error("expected false for missing cgroup dir")
	}
}

func TestStatCgroupDir_Exists(t *testing.T) {
	base := withCgroupBase(t)
	dir := filepath.Join(base, "grp")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if !statCgroupDir(dir) {
		t.Error("expected true when cgroup dir exists under base")
	}
}
