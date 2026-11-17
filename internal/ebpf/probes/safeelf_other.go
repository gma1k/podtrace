//go:build !linux

package probes

import (
	"debug/elf"
	"errors"
	"os"
)

func openELFWithinRoot(_, _ string) (*elf.File, error) {
	return nil, errors.New("openELFWithinRoot: unsupported on this platform")
}

func openVerifiedELFWithinRoot(_, _ string, _ func(*os.File, os.FileInfo, *elf.File) bool) (*elf.File, error) {
	return nil, errors.New("openVerifiedELFWithinRoot: unsupported on this platform")
}

func confirmWithinRoot(_, _, hostPath string) bool {
	fi, err := os.Stat(hostPath)
	return err == nil && fi.Mode().IsRegular()
}
