package events

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestTimestampTime_AnchorsToWallClock is a regression test for the
// monotonic-vs-epoch timestamp bug: Event.Timestamp carries a raw
// bpf_ktime_get_ns() value (CLOCK_MONOTONIC nanoseconds since boot), and
// TimestampTime() used to feed it to time.Unix directly, placing every event
// in January 1970 plus uptime. An event stamped "now" in the BPF time domain
// must convert to a wall-clock time close to time.Now().
func TestTimestampTime_AnchorsToWallClock(t *testing.T) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatalf("ClockGettime(CLOCK_MONOTONIC): %v", err)
	}
	e := &Event{Timestamp: uint64(ts.Sec*int64(time.Second) + ts.Nsec)}

	got := e.TimestampTime()
	if d := time.Since(got); d < -time.Minute || d > time.Minute {
		t.Errorf("TimestampTime() = %v, want within a minute of now (%v); off by %v", got, time.Now(), d)
	}
}

// TestTimestampTime_PreservesDeltas verifies that anchoring does not distort
// relative timing between two events.
func TestTimestampTime_PreservesDeltas(t *testing.T) {
	e1 := &Event{Timestamp: 1_000_000_000}
	e2 := &Event{Timestamp: 3_500_000_000}
	if d := e2.TimestampTime().Sub(e1.TimestampTime()); d != 2500*time.Millisecond {
		t.Errorf("delta = %v, want 2.5s", d)
	}
}
