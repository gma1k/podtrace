// Package procfs offers scoped read access to the procfs filesystem.
//
// Direct calls to os.ReadFile or os.Stat with a path constructed from
// a PID variable are reported as G304 (CWE-22) by static analyzers
// because, in principle, an attacker-controlled component of the path
// could escape the intended directory. In practice, podtrace reads
// procfs files using PIDs emitted by the kernel via BPF events — they
// cannot escape /proc — but the analysis tools can't see that.
//
// This package opens config.ProcBasePath as an os.Root and exposes
// helpers that take relative paths within it. Path-traversal escapes
// are rejected by the kernel-level os.Root machinery (Go 1.24+), and
// gosec/CodeQL recognise the scoped operation as safe. The result is
// fewer false-positive alerts and a single, audited code path for
// every procfs read in the binary.
//
// All exported helpers are safe to call concurrently. The underlying
// *os.Root is opened lazily on first use; callers in tests that
// override config.ProcBasePath should call ResetForTesting between
// runs to reopen against the new path.
package procfs

import (
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"github.com/podtrace/podtrace/internal/config"
)

var (
	rootMu  sync.RWMutex
	rootImp atomic.Pointer[os.Root]
)

// rootForBase returns the open *os.Root for path, opening it on first
// use. The cached root is keyed by path so a tests that mutates
// ProcBasePath sees a fresh open.
func rootForBase(path string) (*os.Root, error) {
	if r := rootImp.Load(); r != nil && r.Name() == path {
		return r, nil
	}
	rootMu.Lock()
	defer rootMu.Unlock()
	if r := rootImp.Load(); r != nil && r.Name() == path {
		return r, nil
	}
	r, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	if old := rootImp.Swap(r); old != nil {
		_ = old.Close()
	}
	return r, nil
}

// ResetForTesting forces the next operation to reopen the procfs
// root. Use in tests that swap config.ProcBasePath at runtime.
func ResetForTesting() {
	rootMu.Lock()
	defer rootMu.Unlock()
	if old := rootImp.Swap(nil); old != nil {
		_ = old.Close()
	}
}

// ReadFile reads a file under config.ProcBasePath. The path must be
// expressed relative to the procfs root, e.g. "1234/cmdline" or
// "self/auxv". Absolute paths and ".." traversals are rejected by the
// underlying os.Root.
func ReadFile(rel string) ([]byte, error) {
	r, err := rootForBase(config.ProcBasePath)
	if err != nil {
		return nil, fmt.Errorf("procfs: open %s: %w", config.ProcBasePath, err)
	}
	f, err := r.Open(rel)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

// Stat returns FileInfo for a path within procfs.
func Stat(rel string) (os.FileInfo, error) {
	r, err := rootForBase(config.ProcBasePath)
	if err != nil {
		return nil, fmt.Errorf("procfs: open %s: %w", config.ProcBasePath, err)
	}
	return r.Stat(rel)
}

// Open opens a file within procfs. The caller must Close the returned
// file. Suitable for streaming readers (e.g. bufio.Scanner over
// /proc/<pid>/maps).
func Open(rel string) (*os.File, error) {
	r, err := rootForBase(config.ProcBasePath)
	if err != nil {
		return nil, fmt.Errorf("procfs: open %s: %w", config.ProcBasePath, err)
	}
	return r.Open(rel)
}

// Readlink returns the target of a symbolic link inside procfs. The
// returned target is whatever the kernel reported (typically an
// absolute path); callers that need to verify the target stays inside
// procfs must do so themselves.
func Readlink(rel string) (string, error) {
	r, err := rootForBase(config.ProcBasePath)
	if err != nil {
		return "", fmt.Errorf("procfs: open %s: %w", config.ProcBasePath, err)
	}
	return r.Readlink(rel)
}
