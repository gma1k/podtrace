//go:build linux

package tracer

import "golang.org/x/sys/unix"

func setDumpable() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0)
}