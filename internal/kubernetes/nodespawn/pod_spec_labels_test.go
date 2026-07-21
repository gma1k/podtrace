package nodespawn

import (
	"strings"
	"testing"
)

func TestSanitizeLabelValue(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"already valid", "my-host_1.2", "my-host_1.2"},
		{"trims surrounding whitespace", "  laptop  ", "laptop"},
		{"invalid chars become underscore", "host!@#name", "host___name"},
		{"trims leading/trailing separators", "-_.host._-", "host"},
		{"empty input yields unknown", "", "unknown"},
		{"all-invalid collapses to unknown", "!!!", "unknown"},
		{"only separators yields unknown", "---", "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeLabelValue(tc.in); got != tc.want {
				t.Errorf("sanitizeLabelValue(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSanitizeLabelValue_TruncatesTo63(t *testing.T) {
	got := sanitizeLabelValue(strings.Repeat("a", 200))
	if len(got) > 63 {
		t.Errorf("sanitized value length = %d, want <= 63", len(got))
	}
	if got != strings.Repeat("a", 63) {
		t.Errorf("unexpected truncation result: %q", got)
	}
}

func TestRandomSuffix_UniqueHex(t *testing.T) {
	a, err := randomSuffix()
	if err != nil {
		t.Fatalf("randomSuffix: %v", err)
	}
	b, err := randomSuffix()
	if err != nil {
		t.Fatalf("randomSuffix: %v", err)
	}
	if len(a) != 8 {
		t.Errorf("suffix length = %d, want 8 (4 bytes hex-encoded)", len(a))
	}
	for _, c := range a {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Errorf("suffix %q has non-hex char %q", a, c)
		}
	}
	if a == b {
		t.Errorf("two random suffixes collided: %q", a)
	}
}
