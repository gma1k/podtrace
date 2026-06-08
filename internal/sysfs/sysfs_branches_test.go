package sysfs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCgroupOpen_RootOpenFails(t *testing.T) {
	withCgroupBase(t, "/no/such/cgroup/base")
	_, err := CgroupOpen("cgroup.procs")
	if err == nil {
		t.Fatal("expected error when cgroup root cannot be opened")
	}
	if !strings.Contains(err.Error(), "sysfs") {
		t.Errorf("error should be wrapped with sysfs prefix, got %v", err)
	}
}

func TestCgroupOpen_Success(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "memory.max"), []byte("max\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	withCgroupBase(t, dir)
	f, err := CgroupOpen("memory.max")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = f.Close() }()
}

func TestCgroupStat_RootOpenFails(t *testing.T) {
	withCgroupBase(t, "/no/such/cgroup/base")
	_, err := CgroupStat("cgroup.procs")
	if err == nil {
		t.Fatal("expected error when cgroup root cannot be opened")
	}
	if !strings.Contains(err.Error(), "sysfs") {
		t.Errorf("error should be wrapped with sysfs prefix, got %v", err)
	}
}

func TestCgroupStat_Success(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cpu.max"), []byte("max 100000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	withCgroupBase(t, dir)
	fi, err := CgroupStat("cpu.max")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fi.IsDir() {
		t.Errorf("expected a regular file, got directory")
	}
}

func TestCgroupStat_MissingRelative(t *testing.T) {
	withCgroupBase(t, t.TempDir())
	if _, err := CgroupStat("does-not-exist"); err == nil {
		t.Fatal("expected error for missing relative path")
	}
}
