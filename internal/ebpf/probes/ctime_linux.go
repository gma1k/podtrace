//go:build linux

package probes

import "syscall"

// changeTimeNs is the inode change time of st.
func changeTimeNs(st *syscall.Stat_t) int64 { return st.Ctim.Nano() }
