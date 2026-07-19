package profiling

import (
	"testing"
	"unicode/utf8"
)

func TestTruncate_RuneSafeNoPanic(t *testing.T) {
	s := "café"
	for max := -1; max <= len(s)+2; max++ {
		got := truncate(s, max)
		if !utf8.ValidString(got) {
			t.Errorf("truncate(%q, %d) = %q is not valid UTF-8", s, max, got)
		}
	}
	if got := truncate("hello world", 8); got != "hello..." {
		t.Errorf("ASCII truncate regressed: got %q, want %q", got, "hello...")
	}
}
