// Package clock anchors BPF timestamps to wall-clock time.
//
// bpf_ktime_get_ns() returns nanoseconds since boot on CLOCK_MONOTONIC, not
// nanoseconds since the Unix epoch. Interpreting such a value as epoch time
// places every event in January 1970 (plus uptime). This package computes the
// offset between the two clocks once per process and converts in both
// directions. It is a leaf package so that low-level packages such as
// internal/events can depend on it without import cycles.
package clock

import (
	"math"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

var (
	offsetOnce sync.Once
	offset     int64 // nanoseconds: wall-clock ns - CLOCK_MONOTONIC ns
)

// MonotonicToWallOffset returns the offset in nanoseconds between wall-clock
// time (time.Now().UnixNano()) and CLOCK_MONOTONIC (the clock behind
// bpf_ktime_get_ns()). Computed once on first call and cached for the process
// lifetime; a wall-clock step (e.g. NTP) after that point shifts converted
// times by the step size, which keeps relative ordering intact.
func MonotonicToWallOffset() int64 {
	offsetOnce.Do(func() {
		var ts unix.Timespec
		// Read CLOCK_MONOTONIC — same clock source as bpf_ktime_get_ns().
		if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err == nil {
			monotonicNS := ts.Sec*int64(time.Second) + ts.Nsec
			wallNS := time.Now().UnixNano()
			offset = wallNS - monotonicNS
		}
		// If ClockGettime fails (unlikely), the offset stays 0 — converted
		// times degrade to boot-relative values but stay internally
		// consistent, so deltas and ordering still work.
	})
	return offset
}

// BPFTimestampToWall converts a bpf_ktime_get_ns() timestamp (nanoseconds
// since boot, CLOCK_MONOTONIC) to a wall-clock time.Time.
func BPFTimestampToWall(bpfNS uint64) time.Time {
	if bpfNS > math.MaxInt64 {
		bpfNS = math.MaxInt64
	}
	return time.Unix(0, int64(bpfNS)+MonotonicToWallOffset())
}

// WallToBPFTimestamp converts a wall-clock time.Time to the bpf_ktime_get_ns()
// timestamp that BPFTimestampToWall would map back to it. Times before boot
// clamp to 0. Intended for tests and for translating wall-clock deadlines into
// the BPF time domain.
func WallToBPFTimestamp(t time.Time) uint64 {
	bpfNS := t.UnixNano() - MonotonicToWallOffset()
	if bpfNS < 0 {
		return 0
	}
	return uint64(bpfNS)
}
