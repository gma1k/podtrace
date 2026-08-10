package probes

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/gma1k/podtrace/internal/hostfs"
	"github.com/gma1k/podtrace/internal/procfs"
	"github.com/gma1k/podtrace/internal/procmaps"
)

// resolveMappedFile turns a /proc/<pid>/maps entry into a host path naming the
// exact file the traced process mapped.
//
// Resolution stays inside the target's own namespace: either through
// /proc/<pid>/map_files, which the kernel resolves to the backing inode with no
// pathname involved, or through /proc/<pid>/root, which pins the lookup to the
// target's rootfs. The pathname is never interpreted in the agent's own mount
// namespace. On a Kubernetes node that pathname is untrusted input — a pod that
// creates "/usr/lib/x86_64-linux-gnu/libssl.so.3 X" in its own rootfs and maps
// it would otherwise steer the privileged agent onto the node's real libssl and
// have it attach SSL_write/SSL_read uprobes to every process on the host.
//
// map_files wins whenever the two disagree, which also covers a pathname the
// target has since replaced with a symlink out of its rootfs.
func resolveMappedFile(pid uint32, e procmaps.Entry) string {
	backing := fileInProcMapFiles(pid, e.AddrRange)

	var named string
	if e.Named() && !e.Deleted {
		named = fileInProcRoot(pid, e.Path)
	}

	if named == "" {
		if e.Executable() {
			return backing
		}
		return ""
	}
	if backing == "" || sameHostFile(named, backing) {
		return named
	}
	return backing
}

// sameHostFile reports whether two paths name the same inode.
func sameHostFile(a, b string) bool {
	ai, err := hostfs.Stat(a)
	if err != nil {
		return false
	}
	bi, err := hostfs.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}

// mappedFilesMatching returns the resolved host paths of every file-backed
// mapping in pid's address space whose pathname contains one of patterns,
// deduplicated by inode so the several segments a shared library is mapped
// through yield one attach target.
func mappedFilesMatching(pid uint32, patterns []string) []string {
	data, err := procfs.ReadFile(fmt.Sprintf("%d/maps", pid))
	if err != nil {
		return nil
	}

	var paths []string
	seen := make(map[string]struct{})

	for _, e := range procmaps.Parse(data) {
		if !e.Named() || !containsAnyPattern(e.Path, patterns) {
			continue
		}
		resolved := resolveMappedFile(pid, e)
		if resolved == "" {
			continue
		}
		key := inodeKey(resolved)
		if key == "" {
			continue
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		paths = append(paths, resolved)
	}
	return paths
}

func containsAnyPattern(s string, patterns []string) bool {
	for _, p := range patterns {
		if p != "" && strings.Contains(s, p) {
			return true
		}
	}
	return false
}

// inodeKey identifies a file by device and inode so that the same library
// reached through different paths is only attached once.
func inodeKey(path string) string {
	info, err := hostfs.Stat(path)
	if err != nil || info.IsDir() {
		return ""
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return path
	}
	return fmt.Sprintf("%d:%d", uint64(sys.Dev), sys.Ino)
}
