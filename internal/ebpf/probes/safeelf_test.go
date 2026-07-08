package probes

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSafeDebugName(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"plain", "libfoo.so.debug", true},
		{"plain dashed", "my-app.debug", true},
		{"empty", "", false},
		{"dot", ".", false},
		{"dotdot", "..", false},
		{"traversal", "../../../proc/kcore", false},
		{"leading slash absolute", "/etc/shadow", false},
		{"embedded slash", "a/b.debug", false},
		{"nul byte", "a\x00b", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := safeDebugName(tc.in); got != tc.want {
				t.Errorf("safeDebugName(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestOpenELFCapped_RejectsOversized is the HS1 regression: an oversized
// (here sparse) /proc/<pid>/exe must be rejected before parsing, not allocated.
func TestOpenELFCapped_RejectsOversized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "huge")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxELFFileSize + 1); err != nil {
		_ = f.Close()
		t.Skipf("cannot create sparse file: %v", err)
	}
	_ = f.Close()

	if _, err := openELFCapped(path); err == nil {
		t.Errorf("openELFCapped accepted a %d-byte file; must reject over %d", maxELFFileSize+1, maxELFFileSize)
	}
}
