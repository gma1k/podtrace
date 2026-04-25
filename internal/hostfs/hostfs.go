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
//
// gosec rules G304 (file inclusion via variable) and G703 (path
// traversal via taint) flag these accesses because, in the abstract,
// the path could be anything. This package surfaces three helpers
// with the only `// #nosec` annotations in the codebase that admit
// genuinely-unscoped access — every other callsite was migrated to
// procfs / sysfs / ldsoconf.
//
// Each helper validates that the path is absolute and free of "..",
// which prevents traversal-via-relative-path even though the
// destination after symlink resolution is intentionally unconstrained.
// Callers must continue to treat the result as untrusted (e.g. attach
// uprobes only after verifying the underlying file is a real ELF).
package hostfs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ErrInvalidPath is returned when the supplied path is not absolute or
// contains a ".." element.
var ErrInvalidPath = errors.New("hostfs: path must be absolute and contain no '..' elements")

func validate(path string) error {
	if !filepath.IsAbs(path) {
		return ErrInvalidPath
	}
	// Reject any ".." segment in the supplied path. filepath.Clean
	// would collapse them and hide the original intent, so we check
	// the unclean form explicitly.
	for _, seg := range strings.Split(path, string(filepath.Separator)) {
		if seg == ".." {
			return ErrInvalidPath
		}
	}
	return nil
}

// Stat returns FileInfo for an absolute host path. The path is
// validated to be absolute and free of ".." segments before the
// underlying os.Stat fires. Used by probe-attachment code that needs
// to verify a libc or binary exists at a specific location reported
// by /proc/<pid>/maps or /proc/<pid>/cmdline.
func Stat(path string) (os.FileInfo, error) {
	if err := validate(path); err != nil {
		return nil, err
	}
	return os.Stat(path) // #nosec G304,G703 -- intentional cross-namespace stat; validated absolute path with no ".." segments. See package docs.
}

// IsRegularFile is a convenience helper: Stat followed by a non-dir
// check, returning false on any error. Matches the dominant pattern
// in the probe code.
func IsRegularFile(path string) bool {
	info, err := Stat(path)
	return err == nil && !info.IsDir()
}

// WalkRegular invokes fn for every regular (non-directory) file under
// root. Symlinks are followed via os.Stat. Equivalent to filepath.Walk
// with explicit input validation on the root path.
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

// ReadFile reads a file the operator has explicitly designated via a
// CLI flag or environment variable. The path is validated to be
// absolute and free of ".." segments. Use only at boundary code that
// receives an operator-supplied path; do not call from internal code
// that constructs its own path.
func ReadFile(path string) ([]byte, error) {
	if err := validate(path); err != nil {
		return nil, err
	}
	return os.ReadFile(path) // #nosec G304 -- operator-supplied path validated above; CLI flag / env var is the intended source.
}

// WriteFile writes data to a path the operator has explicitly
// designated via a CLI flag. The path is validated to be absolute and
// free of ".." segments. perm is honoured as-is; callers should
// prefer 0o600 unless the file must be world-readable for a sidecar.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	if err := validate(path); err != nil {
		return err
	}
	return os.WriteFile(path, data, perm) // #nosec G304,G306 -- operator-supplied path validated; perm is caller-controlled and reviewed at the call site.
}

// Compile-time check that fs.FileInfo and os.FileInfo are the same.
var _ fs.FileInfo = os.FileInfo(nil)
