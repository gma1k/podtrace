//go:build linux

package safeelf

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// ErrConfinementUnsupported reports a kernel without openat2, where a lookup
// cannot be held inside a root.
var ErrConfinementUnsupported = errors.New("openat2 not supported")

var openat2 = unix.Openat2

// OpenWithinRoot opens rel resolved strictly within rootDir, as if rootDir
// were "/": a "..", an absolute symlink or a magic link in the
// container-controlled path cannot leave it. The file must pass the same
// checks as OpenRegular. Returning the opened file, rather than a path that
// was checked, leaves nothing to swap between the check and the use.
func OpenWithinRoot(rootDir, rel string) (*os.File, os.FileInfo, error) {
	rootFd, err := unix.Open(rootDir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = unix.Close(rootFd) }()

	how := &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	}
	fd, err := openat2(rootFd, rel, how)
	if errors.Is(err, unix.ENOSYS) {
		return nil, nil, ErrConfinementUnsupported
	}
	if err != nil {
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), rel)
	fi, err := checkRegular(f, rel)
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, fi, nil
}
