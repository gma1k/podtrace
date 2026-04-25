// Package sysfs offers scoped read access to the cgroup filesystem
// and other directories under /sys.
//
// Like internal/procfs, this package wraps the kernel pseudo-filesystem
// in an os.Root so static analyzers can prove that file operations
// cannot escape the intended directory. Callers pass relative paths
// and never construct absolute /sys/... strings of their own.
//
// The package supports two roots:
//
//   - The cgroup root (config.CgroupBasePath, default /sys/fs/cgroup),
//     used by tracers and resource monitors to read cgroup.procs,
//     cgroup.controllers, memory.max, cpu.max, etc.
//
//   - The generic /sys root, used for things like /sys/fs/selinux
//     by package internal/system. Most callers will only need cgroups.
//
// Both roots are opened lazily on first use, cached, and rebuilt when
// the corresponding config base path changes — see ResetForTesting.
package sysfs

import (
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"github.com/podtrace/podtrace/internal/config"
)

var (
	cgroupMu  sync.RWMutex
	cgroupImp atomic.Pointer[os.Root]
)

func cgroupRoot() (*os.Root, error) {
	want := config.CgroupBasePath
	if r := cgroupImp.Load(); r != nil && r.Name() == want {
		return r, nil
	}
	cgroupMu.Lock()
	defer cgroupMu.Unlock()
	if r := cgroupImp.Load(); r != nil && r.Name() == want {
		return r, nil
	}
	r, err := os.OpenRoot(want)
	if err != nil {
		return nil, err
	}
	if old := cgroupImp.Swap(r); old != nil {
		_ = old.Close()
	}
	return r, nil
}

// ResetForTesting forces the next operation to reopen the cgroup
// root. Use in tests that swap config.CgroupBasePath at runtime.
func ResetForTesting() {
	cgroupMu.Lock()
	defer cgroupMu.Unlock()
	if old := cgroupImp.Swap(nil); old != nil {
		_ = old.Close()
	}
}

// CgroupReadFile reads a file relative to the cgroup root (default
// /sys/fs/cgroup). The relative path may contain subdirectories.
func CgroupReadFile(rel string) ([]byte, error) {
	r, err := cgroupRoot()
	if err != nil {
		return nil, fmt.Errorf("sysfs: open cgroup root %s: %w", config.CgroupBasePath, err)
	}
	f, err := r.Open(rel)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

// CgroupOpen opens a file under the cgroup root for streaming use.
func CgroupOpen(rel string) (*os.File, error) {
	r, err := cgroupRoot()
	if err != nil {
		return nil, fmt.Errorf("sysfs: open cgroup root %s: %w", config.CgroupBasePath, err)
	}
	return r.Open(rel)
}

// CgroupStat returns FileInfo for a path under the cgroup root.
func CgroupStat(rel string) (os.FileInfo, error) {
	r, err := cgroupRoot()
	if err != nil {
		return nil, fmt.Errorf("sysfs: open cgroup root %s: %w", config.CgroupBasePath, err)
	}
	return r.Stat(rel)
}

// CgroupRelative returns the relative path of a fully-qualified cgroup
// path against config.CgroupBasePath. Returns ("", false) when the
// argument is not actually under the configured base. Use when older
// callers carry full /sys/fs/cgroup/... strings.
func CgroupRelative(absolute string) (string, bool) {
	base := config.CgroupBasePath
	if absolute == base {
		return ".", true
	}
	if len(absolute) > len(base) && absolute[:len(base)] == base && absolute[len(base)] == '/' {
		return absolute[len(base)+1:], true
	}
	return "", false
}
