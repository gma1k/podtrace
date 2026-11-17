//go:build linux

package probes

import (
	"debug/elf"
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/gma1k/podtrace/internal/ebpf/safeelf"
)

// openELFWithinRoot opens rel as an ELF resolved strictly within rootDir
// using openat2(RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS): a "..", an absolute
// segment, or a symlink in the container-controlled path cannot escape
// rootDir, closing the .gnu_debuglink traversal that let the root agent open
// host files such as /proc/kcore.
func openELFWithinRoot(rootDir, rel string) (*elf.File, error) {
	return openVerifiedELFWithinRoot(rootDir, rel, nil)
}

// openVerifiedELFWithinRoot is openELFWithinRoot for a file accept must
// approve. The ELF is parsed on demand from the opened file, never read into
// memory whole: a sparse file declares any size for free.
func openVerifiedELFWithinRoot(rootDir, rel string, accept func(*os.File, os.FileInfo, *elf.File) bool) (*elf.File, error) {
	raw, fi, err := safeelf.OpenWithinRoot(rootDir, rel)
	if err != nil {
		return nil, err
	}
	defer func() { _ = raw.Close() }()
	f, err := elf.Open(safeelf.PinnedPath(raw, rel))
	if err != nil {
		return nil, err
	}
	if accept != nil && !accept(raw, fi, f) {
		_ = f.Close()
		return nil, errDebugFileMismatch
	}
	return f, nil
}

var openat2 = unix.Openat2

// statWithinRoot stats rel resolved strictly within rootDir, the same
// confinement openELFWithinRoot applies. supported is false on a kernel
// without openat2, where no such check is possible.
func statWithinRoot(rootDir, rel string) (st unix.Stat_t, supported bool, err error) {
	rootFd, err := unix.Open(rootDir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return st, true, err
	}
	defer func() { _ = unix.Close(rootFd) }()

	how := &unix.OpenHow{
		Flags:   uint64(unix.O_PATH | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	}
	fd, err := openat2(rootFd, rel, how)
	if errors.Is(err, unix.ENOSYS) {
		return st, false, nil
	}
	if err != nil {
		return st, true, err
	}
	defer func() { _ = unix.Close(fd) }()
	err = unix.Fstat(fd, &st)
	return st, true, err
}

// confirmWithinRoot reports whether hostPath, a path under rootDir with no
// symlink left in it, names the same regular file that rel resolves to when
// the lookup is held inside rootDir.
func confirmWithinRoot(rootDir, rel, hostPath string) bool {
	fi, err := os.Stat(hostPath)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	st, supported, err := statWithinRoot(rootDir, rel)
	if !supported {
		return true
	}
	if err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return false
	}
	sys, ok := fi.Sys().(*syscall.Stat_t)
	return ok && uint64(sys.Dev) == st.Dev && sys.Ino == st.Ino
}
