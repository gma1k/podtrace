//go:build !linux

package safeelf

import (
	"errors"
	"os"
)

// ErrConfinementUnsupported reports a platform without openat2.
var ErrConfinementUnsupported = errors.New("openat2 not supported")

// OpenWithinRoot is unavailable off Linux.
func OpenWithinRoot(_, _ string) (*os.File, os.FileInfo, error) {
	return nil, nil, ErrConfinementUnsupported
}
