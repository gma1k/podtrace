// Package clock anchors BPF timestamps to wall-clock time.
//
// bpf_ktime_get_ns() returns nanoseconds since boot on CLOCK_MONOTONIC, not
// nanoseconds since the Unix epoch.
package clock

import (
	"math"
	"sync"
	"time"

	"github.com/podtrace/podtrace/internal/safeconv"
	"golang.org/x/sys/unix"
)

var (
	offsetOnce sync.Once
	offset     int64
)

// MonotonicToWallOffset returns the offset in nanoseconds between wall-clock
// time (time.Now().UnixNano()) and CLOCK_MONOTONIC (the clock behind
// bpf_ktime_get_ns()).
func MonotonicToWallOffset() int64 {
	offsetOnce.Do(func() {
		var ts unix.Timespec
		if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err == nil {
			monotonicNS := ts.Sec*int64(time.Second) + ts.Nsec
			wallNS := time.Now().UnixNano()
			offset = wallNS - monotonicNS
		}
	})
	return offset
}

// BPFTimestampToWall converts a bpf_ktime_get_ns() timestamp (nanoseconds
// since boot, CLOCK_MONOTONIC) to a wall-clock time.Time.
func BPFTimestampToWall(bpfNS uint64) time.Time {
	if bpfNS > math.MaxInt64 {
		bpfNS = math.MaxInt64
	}
	return time.Unix(0, safeconv.AddInt64(int64(bpfNS), MonotonicToWallOffset()))
}

// WallToBPFTimestamp converts a wall-clock time.Time to the bpf_ktime_get_ns()
// timestamp that BPFTimestampToWall would map back to it.
func WallToBPFTimestamp(t time.Time) uint64 {
	bpfNS := t.UnixNano() - MonotonicToWallOffset()
	if bpfNS < 0 {
		return 0
	}
	return uint64(bpfNS)
}
