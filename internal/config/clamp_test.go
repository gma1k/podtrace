package config

import (
	"math"
	"testing"
)

func TestClampPct(t *testing.T) {
	cases := []struct {
		in, want int
	}{
		{-1, 0},
		{0, 0},
		{1, 1},
		{50, 50},
		{99, 99},
		{100, 100},
		{101, 100},
		{1_000_000, 100},
		{math.MaxInt, 100},
	}
	for _, c := range cases {
		if got := ClampPct(c.in); got != c.want {
			t.Errorf("ClampPct(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestClampUint32(t *testing.T) {
	cases := []struct {
		in   int
		want uint32
	}{
		{-1, 0},
		{0, 0},
		{1, 1},
		{4096, 4096},
		{math.MaxInt32, math.MaxInt32},
		// On 64-bit hosts MaxInt > MaxUint32, so the upper clamp fires.
		{math.MaxInt, math.MaxUint32},
	}
	for _, c := range cases {
		if got := ClampUint32(c.in); got != c.want {
			t.Errorf("ClampUint32(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestClampUint32_BoundaryAtMaxUint32 verifies the explicit upper-bound
// branch — exactly math.MaxUint32 should pass through unchanged on
// 64-bit hosts (where int can hold that value).
func TestClampUint32_BoundaryAtMaxUint32(t *testing.T) {
	if math.MaxInt < math.MaxUint32 {
		t.Skip("32-bit host; int cannot represent MaxUint32 unchanged")
	}
	if got := ClampUint32(math.MaxUint32); got != math.MaxUint32 {
		t.Errorf("ClampUint32(MaxUint32) = %d, want MaxUint32", got)
	}
	if got := ClampUint32(math.MaxUint32 + 1); got != math.MaxUint32 {
		t.Errorf("ClampUint32(MaxUint32+1) should clamp, got %d", got)
	}
}

// TestAlertPctClampedAtPackageLoad verifies the package-level
// AlertWarnPct/AlertCritPct/AlertEmergPct went through ClampPct. We
// can't easily reset the env after init runs, so we just assert the
// invariant 0 <= value <= 100 holds for the live values.
func TestAlertPctClampedAtPackageLoad(t *testing.T) {
	for name, v := range map[string]int{
		"AlertWarnPct":  AlertWarnPct,
		"AlertCritPct":  AlertCritPct,
		"AlertEmergPct": AlertEmergPct,
	} {
		if v < 0 || v > 100 {
			t.Errorf("%s = %d, expected to be clamped into [0, 100]", name, v)
		}
	}
}
