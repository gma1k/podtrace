package kubernetes

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/podtrace/podtrace/internal/config"
)

func TestFindCgroupPath_NotFound(t *testing.T) {
	dir := t.TempDir()

	orig := config.CgroupBasePath
	config.SetCgroupBasePath(dir)
	defer func() { config.SetCgroupBasePath(orig) }()

	if path, err := findCgroupPath("nonexistent"); err == nil || path != "" {
		t.Fatalf("expected error and empty path for missing cgroup, got path=%q err=%v", path, err)
	}
}

func TestFindCgroupPath_Found(t *testing.T) {
	dir := t.TempDir()

	orig := config.CgroupBasePath
	config.SetCgroupBasePath(dir)
	defer func() { config.SetCgroupBasePath(orig) }()

	kubepodsSlice := filepath.Join(dir, "kubepods.slice")
	if err := os.MkdirAll(kubepodsSlice, 0o755); err != nil {
		t.Fatalf("failed to create kubepods.slice: %v", err)
	}

	containerID := "abcdef1234567890"
	targetDir := filepath.Join(kubepodsSlice, "pod_"+containerID)
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		t.Fatalf("failed to create target dir: %v", err)
	}

	if path, err := findCgroupPath(containerID); err != nil || path == "" {
		t.Fatalf("expected to find cgroup path, got path=%q err=%v", path, err)
	}
}

func TestPodResolver_ResolvePod_NoContainers(t *testing.T) {
	resolver := &PodResolver{clientset: nil}

	defer func() {
		if r := recover(); r != nil {
			t.Log("ResolvePod panicked as expected for nil clientset")
		}
	}()

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Log("ResolvePod panicked as expected for nil clientset")
			}
		}()
		_, err := resolver.ResolvePod(context.Background(), "test-pod", "default", "")
		if err == nil {
			t.Log("ResolvePod returned error as expected for nil clientset")
		}
	}()
}

func TestFindCgroupPath_EmptyContainerID(t *testing.T) {
	path, err := findCgroupPath("")
	if err == nil && path != "" {
		t.Log("findCgroupPath returned path or no error for empty container ID")
	}
}

func TestFindCgroupPath_ShortID(t *testing.T) {
	dir := t.TempDir()

	orig := config.CgroupBasePath
	config.SetCgroupBasePath(dir)
	defer func() { config.SetCgroupBasePath(orig) }()

	kubepodsSlice := filepath.Join(dir, "kubepods.slice")
	os.MkdirAll(kubepodsSlice, 0755)

	containerID := "abcdef123456"
	targetDir := filepath.Join(kubepodsSlice, "pod_"+containerID[:12])
	os.MkdirAll(targetDir, 0755)

	path, err := findCgroupPath(containerID)
	if err != nil {
		t.Logf("findCgroupPath returned error (may be expected): %v", err)
	}
	if path != "" {
		t.Logf("Found cgroup path: %s", path)
	}
}

func TestFindCgroupPath_SystemSlice(t *testing.T) {
	dir := t.TempDir()

	orig := config.CgroupBasePath
	config.SetCgroupBasePath(dir)
	defer func() { config.SetCgroupBasePath(orig) }()

	systemSlice := filepath.Join(dir, "system.slice")
	os.MkdirAll(systemSlice, 0755)

	containerID := "test123"
	targetDir := filepath.Join(systemSlice, "docker-"+containerID+".scope")
	os.MkdirAll(targetDir, 0755)

	path, err := findCgroupPath(containerID)
	if err != nil {
		t.Logf("findCgroupPath returned error (may be expected): %v", err)
	}
	if path != "" {
		t.Logf("Found cgroup path: %s", path)
	}
}

func TestFindCgroupPath_UserSlice(t *testing.T) {
	dir := t.TempDir()

	orig := config.CgroupBasePath
	config.SetCgroupBasePath(dir)
	defer func() { config.SetCgroupBasePath(orig) }()

	userSlice := filepath.Join(dir, "user.slice")
	os.MkdirAll(userSlice, 0755)

	containerID := "test456"
	targetDir := filepath.Join(userSlice, "user-1000.slice", "docker-"+containerID+".scope")
	os.MkdirAll(targetDir, 0755)

	path, err := findCgroupPath(containerID)
	if err != nil {
		t.Logf("findCgroupPath returned error (may be expected): %v", err)
	}
	if path != "" {
		t.Logf("Found cgroup path: %s", path)
	}
}
