//go:build !linux

package probes

import "syscall"

// changeTimeNs is unavailable off Linux, where no uprobe is attached.
func changeTimeNs(_ *syscall.Stat_t) int64 { return 0 }
