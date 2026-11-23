package clock

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type fakeClock struct {
	at       time.Time
	offset   int64
	ok       bool
	measured int
}

func installFakeClock(t *testing.T, offset int64) *fakeClock {
	t.Helper()
	f := &fakeClock{at: time.Unix(1_700_000_000, 0), offset: offset, ok: true}
	prevNow, prevSample, prevAnchor := now, sampleOffset, current.Load()
	now = func() time.Time { return f.at }
	sampleOffset = func() (int64, bool) {
		f.measured++
		return f.offset, f.ok
	}
	current.Store(nil)
	t.Cleanup(func() {
		now, sampleOffset = prevNow, prevSample
		current.Store(prevAnchor)
	})
	return f
}

func TestOffsetFollowsAWallClockStep(t *testing.T) {
	f := installFakeClock(t, 1_000*int64(time.Second))
	if got := MonotonicToWallOffset(); got != 1_000*int64(time.Second) {
		t.Fatalf("initial offset = %d", got)
	}

	f.offset += int64(90 * time.Second)
	f.at = f.at.Add(recheckInterval)
	if got := MonotonicToWallOffset(); got != 1_090*int64(time.Second) {
		t.Errorf("offset after a 90s step = %d, want %d", got, 1_090*int64(time.Second))
	}

	wall := BPFTimestampToWall(5 * uint64(time.Second))
	if want := time.Unix(1_095, 0); !wall.Equal(want) {
		t.Errorf("converted timestamp after the step = %v, want %v", wall, want)
	}
}

func TestOffsetFollowsABackwardStep(t *testing.T) {
	f := installFakeClock(t, 1_000*int64(time.Second))
	MonotonicToWallOffset()

	f.offset -= int64(2 * time.Second)
	f.at = f.at.Add(recheckInterval)
	if got := MonotonicToWallOffset(); got != 998*int64(time.Second) {
		t.Errorf("offset after a -2s step = %d, want %d", got, 998*int64(time.Second))
	}
}

func TestOffsetIgnoresMeasurementJitter(t *testing.T) {
	f := installFakeClock(t, 1_000*int64(time.Second))
	first := MonotonicToWallOffset()

	f.offset += stepThreshold
	f.at = f.at.Add(recheckInterval)
	if got := MonotonicToWallOffset(); got != first {
		t.Errorf("offset moved by jitter within the threshold: %d -> %d", first, got)
	}

	f.offset = first - stepThreshold
	f.at = f.at.Add(recheckInterval)
	if got := MonotonicToWallOffset(); got != first {
		t.Errorf("offset moved by negative jitter within the threshold: %d -> %d", first, got)
	}
}

func TestOffsetIsNotRemeasuredWithinTheRecheckInterval(t *testing.T) {
	f := installFakeClock(t, 1_000*int64(time.Second))
	MonotonicToWallOffset()

	f.offset += int64(time.Hour)
	f.at = f.at.Add(recheckInterval - time.Nanosecond)
	if got := MonotonicToWallOffset(); got != 1_000*int64(time.Second) {
		t.Errorf("offset changed before the recheck interval elapsed: %d", got)
	}
	if f.measured != 1 {
		t.Errorf("measured %d times, want 1", f.measured)
	}
}

func TestOffsetKeepsTheLastGoodValueWhenMeasurementFails(t *testing.T) {
	f := installFakeClock(t, 1_000*int64(time.Second))
	MonotonicToWallOffset()

	f.ok = false
	f.offset = 0
	f.at = f.at.Add(recheckInterval)
	if got := MonotonicToWallOffset(); got != 1_000*int64(time.Second) {
		t.Errorf("offset after a failed measurement = %d, want the last good value", got)
	}
}

func TestOffsetIsZeroWhenTheFirstMeasurementFails(t *testing.T) {
	f := installFakeClock(t, 1_000*int64(time.Second))
	f.ok = false
	if got := MonotonicToWallOffset(); got != 0 {
		t.Errorf("offset with no measurement = %d, want 0", got)
	}

	f.ok = true
	f.at = f.at.Add(recheckInterval)
	if got := MonotonicToWallOffset(); got != 1_000*int64(time.Second) {
		t.Errorf("offset once measurement recovers = %d, want %d", got, 1_000*int64(time.Second))
	}
}

func TestMeasureOffsetMatchesTheRealClocks(t *testing.T) {
	measured, ok := measureOffset()
	if !ok {
		t.Fatal("measureOffset failed")
	}
	again, _ := measureOffset()
	if d := absDiff(measured, again); d > stepThreshold {
		t.Errorf("two back-to-back measurements differ by %v", time.Duration(d))
	}
}

func TestMeasureOffsetReportsAClockFailure(t *testing.T) {
	orig := clockGettime
	t.Cleanup(func() { clockGettime = orig })
	for failOn := 1; failOn <= 2; failOn++ {
		calls := 0
		clockGettime = func(id int32, ts *unix.Timespec) error {
			calls++
			if calls == failOn {
				return unix.EINVAL
			}
			return orig(id, ts)
		}
		if _, ok := measureOffset(); ok {
			t.Errorf("measureOffset succeeded although clock read %d failed", failOn)
		}
	}
}
