package sanitize

import "testing"

func TestAStrayC1ByteIsReplaced(t *testing.T) {
	for in, want := range map[string]string{
		"a\x9b2Jb":     "a�2Jb",
		"\x9b\x9b":     "��",
		"x\xffy":       "x�y",
		"münchen":      "münchen",
		"keep � as is": "keep � as is",
	} {
		if got := Terminal(in); got != want {
			t.Errorf("Terminal(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidUTF8ReplacesOnlyInvalidBytes(t *testing.T) {
	for in, want := range map[string]string{
		"/data/caf\xc3":  "/data/caf�",
		"x\xffy":         "x�y",
		"münchen":        "münchen",
		"tab\tand\nline": "tab\tand\nline",
		"\x1b[31mred":    "\x1b[31mred",
		"":               "",
	} {
		if got := ValidUTF8(in); got != want {
			t.Errorf("ValidUTF8(%q) = %q, want %q", in, got, want)
		}
	}
}
