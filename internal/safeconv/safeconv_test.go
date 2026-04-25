package safeconv

import (
	"math"
	"testing"
)

func TestUint64ToInt64(t *testing.T) {
	cases := []struct {
		in   uint64
		want int64
	}{
		{0, 0},
		{42, 42},
		{math.MaxInt64, math.MaxInt64},
		{math.MaxInt64 + 1, math.MaxInt64},
		{math.MaxUint64, math.MaxInt64},
	}
	for _, c := range cases {
		if got := Uint64ToInt64(c.in); got != c.want {
			t.Errorf("Uint64ToInt64(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestUint64BitsToInt64(t *testing.T) {
	// Bit-preserving: high-bit-set inputs become negative, sentinel
	// encodings round-trip exactly.
	cases := []struct {
		in   uint64
		want int64
	}{
		{0, 0},
		{42, 42},
		{0x8000000000000000, math.MinInt64},        // high bit only
		{0xFFFFFFFFFFFFFFFF, -1},                   // all-ones → -1
		{math.MaxInt64, math.MaxInt64},
	}
	for _, c := range cases {
		if got := Uint64BitsToInt64(c.in); got != c.want {
			t.Errorf("Uint64BitsToInt64(%#x) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestUint64ToInt32(t *testing.T) {
	cases := []struct {
		in   uint64
		want int32
	}{
		{0, 0},
		{1000, 1000},
		{math.MaxInt32, math.MaxInt32},
		{math.MaxInt32 + 1, math.MaxInt32},
		{math.MaxUint64, math.MaxInt32},
	}
	for _, c := range cases {
		if got := Uint64ToInt32(c.in); got != c.want {
			t.Errorf("Uint64ToInt32(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestUint64ToUint32(t *testing.T) {
	cases := []struct {
		in   uint64
		want uint32
	}{
		{0, 0},
		{42, 42},
		{math.MaxUint32, math.MaxUint32},
		{math.MaxUint32 + 1, math.MaxUint32},
		{math.MaxUint64, math.MaxUint32},
	}
	for _, c := range cases {
		if got := Uint64ToUint32(c.in); got != c.want {
			t.Errorf("Uint64ToUint32(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestInt32ToUint32(t *testing.T) {
	cases := []struct {
		in   int32
		want uint32
	}{
		{0, 0},
		{42, 42},
		{math.MaxInt32, math.MaxInt32},
		{-1, 0},
		{math.MinInt32, 0},
	}
	for _, c := range cases {
		if got := Int32ToUint32(c.in); got != c.want {
			t.Errorf("Int32ToUint32(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestInt64ToUint64(t *testing.T) {
	cases := []struct {
		in   int64
		want uint64
	}{
		{0, 0},
		{42, 42},
		{math.MaxInt64, math.MaxInt64},
		{-1, 0},
		{math.MinInt64, 0},
	}
	for _, c := range cases {
		if got := Int64ToUint64(c.in); got != c.want {
			t.Errorf("Int64ToUint64(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestIntToInt32(t *testing.T) {
	cases := []struct {
		in   int
		want int32
	}{
		{0, 0},
		{42, 42},
		{-42, -42},
		{math.MaxInt32, math.MaxInt32},
		{math.MinInt32, math.MinInt32},
		{math.MaxInt32 + 1, math.MaxInt32},
		{math.MinInt32 - 1, math.MinInt32},
	}
	for _, c := range cases {
		if got := IntToInt32(c.in); got != c.want {
			t.Errorf("IntToInt32(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestInt64ToUint32(t *testing.T) {
	cases := []struct {
		in   int64
		want uint32
	}{
		{0, 0},
		{42, 42},
		{-1, 0},
		{math.MinInt64, 0},
		{math.MaxUint32, math.MaxUint32},
		{math.MaxUint32 + 1, math.MaxUint32},
		{math.MaxInt64, math.MaxUint32},
	}
	for _, c := range cases {
		if got := Int64ToUint32(c.in); got != c.want {
			t.Errorf("Int64ToUint32(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestIntToUint32(t *testing.T) {
	cases := []struct {
		in   int
		want uint32
	}{
		{0, 0},
		{42, 42},
		{-1, 0},
		{math.MaxInt32, math.MaxInt32},
		{math.MaxUint32, math.MaxUint32},
		{math.MaxUint32 + 1, math.MaxUint32},
	}
	for _, c := range cases {
		if got := IntToUint32(c.in); got != c.want {
			t.Errorf("IntToUint32(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}
