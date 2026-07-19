// Package hostfs provides explicit, audited access to filesystem
// paths that intentionally cross trust boundaries.
//
// Most filesystem access in podtrace is scoped via internal/procfs and
// internal/sysfs, which use os.Root to prevent traversal escapes. A
// few code paths must legitimately operate on paths that no os.Root
// can scope:
//
//   - /proc/<pid>/root/<container-path> — traversing through the
//     kernel's per-process mount-namespace symlink to find a libc or
//     SSL library inside a container's rootfs. The kernel's pid/root
//     symlink IS the trust boundary; constraining the destination
//     defeats the purpose of the lookup.
//
//   - $HOME/.kube/config / /home/<sudoUser>/.kube/config — explicit
//     CLI behaviour that follows the operator's environment.
//
//   - filepath.Walk over a host directory derived from ld.so.conf —
//     the entries returned by the linker config are themselves under
//     /usr or /lib and the walker honours symlinks the linker would.
package hostfs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ErrInvalidPath is returned when the supplied path is not absolute or
// contains a ".." element.
var ErrInvalidPath = errors.New("hostfs: path must be absolute and contain no '..' elements")

// ErrUnsafeMode is returned by the write helpers when the requested mode
// grants write permission to group or other.
var ErrUnsafeMode = errors.New("hostfs: refusing to write with a group/other-writable mode")

func validate(path string) error {
	if !filepath.IsAbs(path) {
		return ErrInvalidPath
	}
	for _, seg := range strings.Split(path, string(filepath.Separator)) {
		if seg == ".." {
			return ErrInvalidPath
		}
	}
	return nil
}

// Stat returns FileInfo for an absolute host path. The path is
// validated to be absolute and free of ".." segments before the
// underlying os.Stat fires.
func Stat(path string) (os.FileInfo, error) {
	if err := validate(path); err != nil {
		return nil, err
	}
	return os.Stat(path) // #nosec G304,G703 -- intentional cross-namespace stat; validated absolute path with no ".." segments. See package docs.
}

// IsRegularFile is a convenience helper: Stat followed by a non-dir
// check, returning false on any error.
func IsRegularFile(path string) bool {
	info, err := Stat(path)
	return err == nil && !info.IsDir()
}

// WalkRegular invokes fn for every regular (non-directory) file under
// root. Symlinks are followed via os.Stat.
func WalkRegular(root string, fn func(path string, info os.FileInfo) error) error {
	if err := validate(root); err != nil {
		return err
	}
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error { // #nosec G304,G703 -- root is validated absolute path; per-entry "info" is kernel-provided.
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		return fn(path, info)
	})
}

func Open(path string) (*os.File, error) {
	if err := validate(path); err != nil {
		return nil, err
	}
	return os.Open(path) // #nosec G304 -- intentional cross-namespace open; validated absolute path with no ".." segments.
}

// ReadFile reads a file the operator has explicitly designated via a
// CLI flag or environment variable.
func ReadFile(path string) ([]byte, error) {
	if err := validate(path); err != nil {
		return nil, err
	}
	return os.ReadFile(path) // #nosec G304 -- operator-supplied path validated above; CLI flag / env var is the intended source.
}

// WriteFile writes data to a path the operator has explicitly
// designated via a CLI flag.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	if err := validate(path); err != nil {
		return err
	}
	if perm&0o022 != 0 {
		return fmt.Errorf("%w: %#o (%s)", ErrUnsafeMode, perm, path)
	}
	return os.WriteFile(path, data, perm) // #nosec G304,G306 -- path validated absolute/no-"..", mode asserted non-group/other-writable above; some handoffs pass 0644 so a nonroot sidecar can read a root-written file over a pod-private emptyDir.
}

// ErrOutsideBase is returned by WriteFileWithin when the target path
// resolves outside the permitted base directory.
var ErrOutsideBase = errors.New("hostfs: path escapes the permitted base directory")

// WriteFileWithin is WriteFile plus a base-directory jail: it refuses to
// write anywhere outside baseDir.
func WriteFileWithin(baseDir, path string, data []byte, perm os.FileMode) error {
	if err := ensureWithin(baseDir, path); err != nil {
		return err
	}
	return WriteFile(path, data, perm)
}

// ensureWithin validates baseDir and path (absolute, no "..") and confirms
// path does not escape baseDir.
func ensureWithin(baseDir, path string) error {
	if err := validate(baseDir); err != nil {
		return err
	}
	if err := validate(path); err != nil {
		return err
	}
	rel, err := filepath.Rel(filepath.Clean(baseDir), filepath.Clean(path))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: %s not under %s", ErrOutsideBase, path, baseDir)
	}
	return nil
}

// WriteFileAtomic writes data via a temp file + rename so a concurrent reader
// (e.g. the report-uploader sidecar polling the shared emptyDir) never sees a
// partially-written or empty file.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := validate(path); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Compile-time check that fs.FileInfo and os.FileInfo are the same.
var _ fs.FileInfo = os.FileInfo(nil)
