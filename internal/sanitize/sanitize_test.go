package sanitize

import (
	"strings"
	"testing"
)

func TestTerminal_PreservesCleanText(t *testing.T) {
	clean := []string{
		"",
		"GET /api/v1/users",
		"example.com (https)",
		"münchen.example.de",        // multibyte UTF-8 (IDN host) must survive
		"pool-7:redis://cache:6379", // punctuation, no control chars
	}
	for _, s := range clean {
		if got := Terminal(s); got != s {
			t.Errorf("Terminal(%q) = %q, want unchanged", s, got)
		}
	}
}

func TestTerminal_StripsTerminalEscapes(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"ansi-color", "\x1b[31mDROP TABLE\x1b[0m"},
		{"cursor-move", "safe\x1b[2J\x1b[Hcleared"},
		{"raw-esc", "a\x1bb"},
		{"newline-injection", "GET /x\nFAKE LINE: pwned"},
		{"carriage-return", "overwrite\rme"},
		{"tab", "col1\tcol2"},
		{"nul", "a\x00b"},
		{"del", "a\x7fb"},
		{"c1-control", "a\u0085b"},             // NEL
		{"line-separator", "a\u2028b"},         // U+2028
		{"bidi-override", "user\u202Egnp.exe"}, // Trojan-Source RTL override
		{"bidi-isolate", "a\u2066b\u2069c"},    // LRI / PDI isolates
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Terminal(tc.in)
			if strings.ContainsRune(got, 0x1b) {
				t.Errorf("output still contains ESC: %q", got)
			}
			if i := strings.IndexFunc(got, unsafeRune); i >= 0 {
				t.Errorf("output still contains an unsafe rune at %d: %q", i, got)
			}
			if strings.ContainsRune(got, '\n') || strings.ContainsRune(got, '\r') {
				t.Errorf("output can still forge report lines: %q", got)
			}
		})
	}
}

func TestTerminal_ReplacesWithMarker(t *testing.T) {
	got := Terminal("a\x1bb")
	want := "a" + string(Replacement) + "b"
	if got != want {
		t.Errorf("Terminal(%q) = %q, want %q", "a\x1bb", got, want)
	}
	if !strings.HasPrefix(got, "a") || !strings.HasSuffix(got, "b") {
		t.Errorf("surrounding safe text not preserved: %q", got)
	}
}

func TestTerminal_CleanInputReturnsSameString(t *testing.T) {
	in := "no control chars here"
	if got := Terminal(in); got != in {
		t.Errorf("clean input mutated: %q", got)
	}
}
