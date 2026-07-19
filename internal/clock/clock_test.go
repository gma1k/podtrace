package clock

import (
	"math"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMonotonicToWallOffset_Idempotent(t *testing.T) {
	a := MonotonicToWallOffset()
	b := MonotonicToWallOffset()
	if a != b {
		t.Errorf("MonotonicToWallOffset() not idempotent: %d != %d", a, b)
	}
}

func TestBPFTimestampToWall_AnchorsToWallClock(t *testing.T) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatalf("ClockGettime(CLOCK_MONOTONIC): %v", err)
	}
	bpfNow := uint64(ts.Sec*int64(time.Second) + ts.Nsec)

	got := BPFTimestampToWall(bpfNow)
	if d := time.Since(got); d < -time.Minute || d > time.Minute {
		t.Errorf("BPFTimestampToWall(current ktime) = %v, want within a minute of now (%v); off by %v", got, time.Now(), d)
	}
}

func TestBPFTimestampToWall_Conversion(t *testing.T) {
	offset := MonotonicToWallOffset()

	const bpfNS = uint64(1_000_000_000)
	got := BPFTimestampToWall(bpfNS)
	want := time.Unix(0, int64(bpfNS)+offset)
	if !got.Equal(want) {
		t.Errorf("BPFTimestampToWall(%d) = %v, want %v", bpfNS, got, want)
	}

	gotZero := BPFTimestampToWall(0)
	wantZero := time.Unix(0, offset)
	if !gotZero.Equal(wantZero) {
		t.Errorf("BPFTimestampToWall(0) = %v, want %v", gotZero, wantZero)
	}

	gotBig := BPFTimestampToWall(math.MaxUint64)
	wantBig := time.Unix(0, math.MaxInt64)
	if !gotBig.Equal(wantBig) {
		t.Errorf("BPFTimestampToWall(MaxUint64) = %v, want %v", gotBig, wantBig)
	}
}

func TestBPFTimestampToWall_RelativeOrdering(t *testing.T) {
	t1 := BPFTimestampToWall(1_000_000_000)
	t2 := BPFTimestampToWall(2_000_000_000)
	if !t2.After(t1) {
		t.Errorf("expected t2 > t1, got t1=%v t2=%v", t1, t2)
	}
	if d := t2.Sub(t1); d != time.Second {
		t.Errorf("expected exactly 1s between t1 and t2, got %v", d)
	}
}

func TestWallToBPFTimestamp_RoundTrip(t *testing.T) {
	now := time.Now()
	bpfNS := WallToBPFTimestamp(now)
	back := BPFTimestampToWall(bpfNS)
	if !back.Equal(time.Unix(0, now.UnixNano())) {
		t.Errorf("round trip lost precision: %v -> %d -> %v", now, bpfNS, back)
	}
}

func TestWallToBPFTimestamp_ClampsBeforeBoot(t *testing.T) {
	beforeBoot := time.Unix(0, 0)
	if got := WallToBPFTimestamp(beforeBoot); got != 0 {
		t.Errorf("WallToBPFTimestamp(epoch) = %d, want 0 (clamped)", got)
	}
}
