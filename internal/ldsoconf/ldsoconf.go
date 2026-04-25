// Package ldsoconf reads dynamic-linker search-path configuration from
// /etc/ld.so.conf and /etc/ld.so.conf.d/*.conf using a scoped os.Root.
//
// The probe-attachment code needs the same set of search paths the
// dynamic linker would consider when resolving libc, libssl, etc., so
// it can find a matching shared object on the host or under a
// container's /proc/<pid>/root view. The base directory is whatever
// config.LdSoConfBasePath points to (default /etc).
//
// All exported helpers operate inside the configured base; absolute
// paths and ".." traversals are rejected by os.Root.
package ldsoconf

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/podtrace/podtrace/internal/config"
)

var (
	rootMu  sync.RWMutex
	rootImp atomic.Pointer[os.Root]
)

func openRoot() (*os.Root, error) {
	want := config.LdSoConfBasePath
	if r := rootImp.Load(); r != nil && r.Name() == want {
		return r, nil
	}
	rootMu.Lock()
	defer rootMu.Unlock()
	if r := rootImp.Load(); r != nil && r.Name() == want {
		return r, nil
	}
	r, err := os.OpenRoot(want)
	if err != nil {
		return nil, err
	}
	if old := rootImp.Swap(r); old != nil {
		_ = old.Close()
	}
	return r, nil
}

// ResetForTesting forces the next call to reopen the root. Use in
// tests that mutate config.LdSoConfBasePath.
func ResetForTesting() {
	rootMu.Lock()
	defer rootMu.Unlock()
	if old := rootImp.Swap(nil); old != nil {
		_ = old.Close()
	}
}

func readScoped(rel string) ([]byte, error) {
	r, err := openRoot()
	if err != nil {
		return nil, fmt.Errorf("ldsoconf: open %s: %w", config.LdSoConfBasePath, err)
	}
	f, err := r.Open(rel)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

// SearchPaths returns the dynamic-linker search paths assembled from
// ld.so.conf plus every *.conf entry under ld.so.conf.d/. Empty lines
// and lines starting with '#' are skipped. Errors reading individual
// files are silently ignored — a missing /etc/ld.so.conf on minimal
// containers is normal, and the caller falls back to architecture
// defaults.
func SearchPaths() []string {
	var out []string

	if data, err := readScoped("ld.so.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				out = append(out, line)
			}
		}
	}

	r, err := openRoot()
	if err != nil {
		return out
	}
	entries, err := fs.readDir(r, "ld.so.conf.d")
	if err != nil {
		return out
	}
	for _, name := range entries {
		if !strings.HasSuffix(name, ".conf") {
			continue
		}
		rel := filepath.Join("ld.so.conf.d", name)
		if data, err := readScoped(rel); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					out = append(out, line)
				}
			}
		}
	}
	return out
}

// fs holds tiny utilities used internally so the file does not depend
// on filepath.Glob (which gosec also flags) and stays inside os.Root.
var fs = struct {
	readDir func(r *os.Root, name string) ([]string, error)
}{
	readDir: func(r *os.Root, name string) ([]string, error) {
		f, err := r.Open(name)
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		entries, err := f.Readdirnames(-1)
		if err != nil {
			return nil, err
		}
		return entries, nil
	},
}
