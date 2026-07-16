package probes

import (
	"os"
	"syscall"
)

// AttachedFiles tracks library files already claimed for uprobe attachment
// within one container attach pass.
type AttachedFiles struct {
	seen map[attachedFileKey]struct{}
}

type attachedFileKey struct {
	family string
	dev    uint64
	ino    uint64
}

func NewAttachedFiles() *AttachedFiles {
	return &AttachedFiles{seen: map[attachedFileKey]struct{}{}}
}

// Claim reports whether path is new for this probe family and marks it
// attached.
func (a *AttachedFiles) Claim(family, path string) bool {
	if a == nil {
		return true
	}
	st, err := os.Stat(path)
	if err != nil {
		return true
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	k := attachedFileKey{family: family, dev: uint64(sys.Dev), ino: sys.Ino}
	if _, dup := a.seen[k]; dup {
		return false
	}
	a.seen[k] = struct{}{}
	return true
}
