package safeconv

import (
	"math"
	"testing"
)

func TestFloat64ToInt64(t *testing.T) {
	cases := []struct {
		in   float64
		want int64
	}{
		{0, 0},
		{123.9, 123},
		{-123.9, -123},
		{math.NaN(), 0},
		{math.Inf(1), math.MaxInt64},
		{math.Inf(-1), math.MinInt64},
		{1e300, math.MaxInt64},
		{-1e300, math.MinInt64},
	}
	for _, c := range cases {
		if got := Float64ToInt64(c.in); got != c.want {
			t.Errorf("Float64ToInt64(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestAddInt64(t *testing.T) {
	cases := []struct {
		a, b, want int64
	}{
		{1, 2, 3},
		{-5, 5, 0},
		{math.MaxInt64, 1, math.MaxInt64},
		{math.MaxInt64 - 5, 10, math.MaxInt64},
		{math.MinInt64, -1, math.MinInt64},
		{math.MinInt64 + 5, -10, math.MinInt64},
	}
	for _, c := range cases {
		if got := AddInt64(c.a, c.b); got != c.want {
			t.Errorf("AddInt64(%d, %d) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
