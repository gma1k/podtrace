//go:build !linux

package probes

import (
	"debug/elf"
	"errors"
)

func openELFWithinRoot(_, _ string) (*elf.File, error) {
	return nil, errors.New("openELFWithinRoot: unsupported on this platform")
}