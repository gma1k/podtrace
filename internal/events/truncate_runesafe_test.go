package events

import (
	"testing"
	"unicode/utf8"
)

func TestTruncateString_RuneSafe(t *testing.T) {
	s := "café-service"
	for max := -1; max <= len(s)+2; max++ {
		got := truncateString(s, max)
		if !utf8.ValidString(got) {
			t.Errorf("truncateString(%q, %d) = %q is not valid UTF-8", s, max, got)
		}
		if max > 0 && len(s) > max && len(got) > max {
			t.Errorf("truncateString(%q, %d) = %q exceeds the %d-byte budget", s, max, got, max)
		}
	}
}
