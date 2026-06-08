package tracker

import "testing"

func TestIsTransientName(t *testing.T) {
	cases := map[string]bool{
		"runc-bootstrap[123]": true,
		"runc:[2:INIT]":       true,
		"nginx":               false,
		"":                    false,
		"runc":                false,
	}
	for name, want := range cases {
		if got := isTransientName(name); got != want {
			t.Errorf("isTransientName(%q) = %v, want %v", name, got, want)
		}
	}
}
