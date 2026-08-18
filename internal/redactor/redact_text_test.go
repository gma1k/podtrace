package redactor

import (
	"strings"
	"testing"
)

func TestRedactText_ScrubsSensitivePatterns(t *testing.T) {
	in := "GET /api?token=SECRET123 HTTP/1.1\nCookie: session=abcdef\nAuthorization: Bearer XYZ.abc\ncontact foo@bar.com"
	got := Default().RedactText(in)

	for _, leak := range []string{"SECRET123", "abcdef", "XYZ.abc", "foo@bar.com"} {
		if strings.Contains(got, leak) {
			t.Errorf("RedactText leaked %q: %s", leak, got)
		}
	}
	if !strings.Contains(got, "GET /api") {
		t.Errorf("RedactText destroyed surrounding non-sensitive text: %s", got)
	}
}

func TestRedactText_NoSensitiveDataIsUnchanged(t *testing.T) {
	in := "Total events: 1494\nEvents per second: 49.8\n"
	if got := Default().RedactText(in); got != in {
		t.Errorf("RedactText(%q) = %q, want unchanged", in, got)
	}
}
