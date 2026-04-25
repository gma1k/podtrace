package sysfs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/podtrace/podtrace/internal/config"
)

func withCgroupBase(t *testing.T, base string) {
	t.Helper()
	original := config.CgroupBasePath
	config.CgroupBasePath = base
	ResetForTesting()
	t.Cleanup(func() {
		config.CgroupBasePath = original
		ResetForTesting()
	})
}

func TestCgroupReadFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte("1234\n5678\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	withCgroupBase(t, dir)

	got, err := CgroupReadFile("cgroup.procs")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "1234\n5678\n" {
		t.Errorf("unexpected content: %q", got)
	}
}

func TestCgroupReadFile_TraversalRejected(t *testing.T) {
	dir := t.TempDir()
	withCgroupBase(t, dir)
	if _, err := CgroupReadFile("../etc/passwd"); err == nil {
		t.Fatal("traversal must be rejected")
	}
}

func TestCgroupOpen_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	withCgroupBase(t, dir)
	f, err := CgroupOpen("f")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
}

func TestCgroupStat_Subdir(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "kubepods/pod-x"), 0o755); err != nil {
		t.Fatal(err)
	}
	withCgroupBase(t, dir)
	fi, err := CgroupStat("kubepods/pod-x")
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() {
		t.Errorf("expected directory")
	}
}

func TestCgroupRelative(t *testing.T) {
	withCgroupBase(t, "/sys/fs/cgroup")
	cases := []struct {
		in   string
		rel  string
		ok   bool
	}{
		{"/sys/fs/cgroup", ".", true},
		{"/sys/fs/cgroup/kubepods/pod-1", "kubepods/pod-1", true},
		{"/sys/fs/cgroup/kubepods", "kubepods", true},
		{"/sys/fs/cgroupABC", "", false}, // prefix match must require slash
		{"/etc/passwd", "", false},
	}
	for _, c := range cases {
		rel, ok := CgroupRelative(c.in)
		if rel != c.rel || ok != c.ok {
			t.Errorf("CgroupRelative(%q) = (%q, %v), want (%q, %v)", c.in, rel, ok, c.rel, c.ok)
		}
	}
}

func TestCgroupRoot_FailsOnMissingPath(t *testing.T) {
	withCgroupBase(t, "/non/existent/cgroup")
	_, err := CgroupReadFile("anything")
	if err == nil {
		t.Fatal("expected error")
	}
}
