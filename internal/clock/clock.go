// Package clock anchors BPF timestamps to wall-clock time.
//
// bpf_ktime_get_ns() returns nanoseconds since boot on CLOCK_MONOTONIC, not
// nanoseconds since the Unix epoch.
package clock

import (
	"math"
	"sync/atomic"
	"time"

	"github.com/gma1k/podtrace/internal/safeconv"
	"golang.org/x/sys/unix"
)

const (
	recheckInterval = time.Second

	stepThreshold = int64(time.Millisecond)
)

type anchor struct {
	offset    int64
	checkedAt time.Time
}

var (
	current      atomic.Pointer[anchor]
	now          = time.Now
	sampleOffset = measureOffset
	clockGettime = unix.ClockGettime
)

// measureOffset reads CLOCK_MONOTONIC either side of the wall clock and
// pairs the wall reading with their midpoint.
func measureOffset() (int64, bool) {
	var before, after unix.Timespec
	if err := clockGettime(unix.CLOCK_MONOTONIC, &before); err != nil {
		return 0, false
	}
	wallNS := time.Now().UnixNano()
	if err := clockGettime(unix.CLOCK_MONOTONIC, &after); err != nil {
		return 0, false
	}
	beforeNS := before.Sec*int64(time.Second) + before.Nsec
	afterNS := after.Sec*int64(time.Second) + after.Nsec
	return wallNS - (beforeNS + (afterNS-beforeNS)/2), true
}

// MonotonicToWallOffset returns the offset in nanoseconds between wall-clock
// time (time.Now().UnixNano()) and CLOCK_MONOTONIC (the clock behind
// bpf_ktime_get_ns()).
func MonotonicToWallOffset() int64 {
	t := now()
	a := current.Load()
	if a != nil && t.Sub(a.checkedAt) < recheckInterval {
		return a.offset
	}
	measured, ok := sampleOffset()
	next := &anchor{checkedAt: t}
	switch {
	case !ok && a == nil:
		next.offset = 0
	case !ok:
		next.offset = a.offset
	case a != nil && absDiff(measured, a.offset) <= stepThreshold:
		next.offset = a.offset
	default:
		next.offset = measured
	}
	current.Store(next)
	return next.offset
}

func absDiff(a, b int64) int64 {
	if a > b {
		return a - b
	}
	return b - a
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
