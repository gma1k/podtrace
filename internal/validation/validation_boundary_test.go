package validation

import "testing"

// TestValidatePath_SeparatorBoundary: a bare prefix check accepted
// "/base-evil/secret" as inside "/base" — the boundary must be a path
// separator.
func TestValidatePath_SeparatorBoundary(t *testing.T) {
	cases := []struct {
		path string
		base string
		ok   bool
	}{
		{"/base/file", "/base", true},
		{"/base", "/base", true},
		{"/base/sub/dir", "/base", true},
		{"/base-evil/secret", "/base", false},
		{"/baseline", "/base", false},
		{"/other", "/base", false},
		{"/etc/passwd", "/", true},
	}
	for _, c := range cases {
		err := ValidatePath(c.path, c.base)
		if (err == nil) != c.ok {
			t.Errorf("ValidatePath(%q, %q) error = %v, want ok=%v", c.path, c.base, err, c.ok)
		}
	}
}
