package profiling

import (
	"math"
	"testing"
)

func TestSafeInt64(t *testing.T) {
	cases := []struct {
		name string
		in   uint64
		want int64
	}{
		{"zero", 0, 0},
		{"normal", 42, 42},
		{"maxInt64", uint64(math.MaxInt64), math.MaxInt64},
		{"overflow", uint64(math.MaxInt64) + 1, math.MaxInt64},
		{"maxUint64", math.MaxUint64, math.MaxInt64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := safeInt64(tc.in); got != tc.want {
				t.Errorf("safeInt64(%d) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	cases := []struct {
		name   string
		s      string
		maxLen int
		want   string
	}{
		{"under limit", "hello", 10, "hello"},
		{"exactly at limit", "hello", 5, "hello"},
		{"over limit", "hello world", 8, "hello..."},
		{"single char over", "abcdef", 5, "ab..."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := truncate(tc.s, tc.maxLen); got != tc.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tc.s, tc.maxLen, got, tc.want)
			}
		})
	}
}

func TestFormatBytes(t *testing.T) {
	cases := []struct {
		name string
		in   int64
		want string
	}{
		{"negative", -1, "?"},
		{"zero", 0, "0B"},
		{"bytes", 512, "512B"},
		{"kb boundary", 1024, "1.0KB"},
		{"kb", 1536, "1.5KB"},
		{"mb boundary", 1024 * 1024, "1.0MB"},
		{"mb", 1024 * 1024 * 3 / 2, "1.5MB"},
		{"gb boundary", 1024 * 1024 * 1024, "1.0GB"},
		{"huge", math.MaxInt64, "8589934592.0GB"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatBytes(tc.in); got != tc.want {
				t.Errorf("formatBytes(%d) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
