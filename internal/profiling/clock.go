package profiling

import (
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

var (
	clockOnce   sync.Once
	clockOffset int64 // nanoseconds: wallNS - CLOCK_MONOTONIC_NS
)

// GetClockOffset returns the offset in nanoseconds between wall-clock time
// (time.Now().UnixNano()) and BPF ktime_get_ns() (which uses CLOCK_MONOTONIC).
// Computed once on first call and cached for the process lifetime.
func GetClockOffset() int64 {
	clockOnce.Do(func() {
		var ts unix.Timespec
		// Read CLOCK_MONOTONIC — same clock source as bpf_ktime_get_ns().
		if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err == nil {
			monotonicNS := ts.Sec*int64(time.Second) + ts.Nsec
			wallNS := time.Now().UnixNano()
			clockOffset = wallNS - monotonicNS
		}
		// If ClockGettime fails (unlikely), offset stays 0 — correlation uses
		// relative timing which still works, just without absolute wall-clock anchoring.
	})
	return clockOffset
}

// BPFTimestampToWall converts a BPF ktime_get_ns() timestamp (nanoseconds since
// system boot, CLOCK_MONOTONIC) to a wall-clock time.Time.
func BPFTimestampToWall(bpfNS uint64) time.Time {
	return time.Unix(0, int64(bpfNS)+GetClockOffset())
}
