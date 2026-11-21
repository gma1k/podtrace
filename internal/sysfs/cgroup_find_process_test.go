package sysfs

import (
	"os"
	"path/filepath"
	"testing"
)

func writeProcs(t *testing.T, base, rel, content string) {
	t.Helper()
	dir := filepath.Join(base, rel)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCgroupFindProcessFindsTheCgroupListingThePid(t *testing.T) {
	base := t.TempDir()
	withCgroupBase(t, base)
	writeProcs(t, base, ".", "1\n2\n")
	writeProcs(t, base, "kubepods/pod-a/ctr", "4242\n")
	writeProcs(t, base, "kubepods/pod-b/ctr", "424\n42420\n")
	writeProcs(t, base, "kubepods/pod-c/agent", "17\n4243\n")

	got, ok := CgroupFindProcess(4243)
	if !ok || got != "kubepods/pod-c/agent" {
		t.Fatalf("CgroupFindProcess = %q, %v", got, ok)
	}
	if got, ok := CgroupFindProcess(1); !ok || got != "." {
		t.Fatalf("a pid in the root cgroup = %q, %v", got, ok)
	}
	if got, ok := CgroupFindProcess(99); ok {
		t.Fatalf("an absent pid was found in %q", got)
	}
}

func TestCgroupFindProcessFailsWithoutACgroupRoot(t *testing.T) {
	withCgroupBase(t, filepath.Join(t.TempDir(), "missing"))
	if _, ok := CgroupFindProcess(1); ok {
		t.Fatal("found a pid without a cgroup root")
	}
}

func TestCgroupFindProcessSkipsACgroupWhoseProcsCannotBeRead(t *testing.T) {
	base := t.TempDir()
	withCgroupBase(t, base)
	if err := os.MkdirAll(filepath.Join(base, "broken", "cgroup.procs"), 0o750); err != nil {
		t.Fatal(err)
	}
	writeProcs(t, base, "open", "7\n")

	if got, ok := CgroupFindProcess(7); !ok || got != "open" {
		t.Fatalf("CgroupFindProcess = %q, %v; an unreadable cgroup.procs must not stop the search", got, ok)
	}
}

func TestCgroupFindProcessStopsAtTheSearchLimit(t *testing.T) {
	base := t.TempDir()
	withCgroupBase(t, base)
	writeProcs(t, base, "deep/agent", "7\n")
	orig := cgroupSearchLimit
	cgroupSearchLimit = 1
	t.Cleanup(func() { cgroupSearchLimit = orig })

	if got, ok := CgroupFindProcess(7); ok {
		t.Fatalf("found %q past the search limit", got)
	}
}

func TestCgroupFindProcessSkipsADirectoryItCannotList(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lists a directory regardless of its mode")
	}
	base := t.TempDir()
	withCgroupBase(t, base)
	locked := filepath.Join(base, "a-locked")
	if err := os.Mkdir(locked, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	writeProcs(t, base, "b-open", "7\n")

	if got, ok := CgroupFindProcess(7); !ok || got != "b-open" {
		t.Fatalf("CgroupFindProcess = %q, %v; a directory that cannot be listed must not stop the search", got, ok)
	}
}
