//go:build linux

package probes

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// openELFWithinRoot opens rel as an ELF resolved strictly within rootDir using
// openat2(RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS): a "..", an absolute segment,
// or a symlink in the container-controlled path cannot escape rootDir, closing
// the .gnu_debuglink traversal that let the root agent open host files such as
// /proc/kcore.
func openELFWithinRoot(rootDir, rel string) (*elf.File, error) {
	rootFd, err := unix.Open(rootDir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(rootFd) }()

	how := &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	}
	fd, err := unix.Openat2(rootFd, rel, how)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), rel)
	defer func() { _ = file.Close() }()

	fi, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("debug file %q is not a regular file", rel)
	}
	if fi.Size() > maxELFFileSize {
		return nil, fmt.Errorf("debug file %q too large: %d bytes", rel, fi.Size())
	}
	buf := make([]byte, fi.Size())
	if _, err := io.ReadFull(file, buf); err != nil {
		return nil, err
	}
	return elf.NewFile(bytes.NewReader(buf))
}