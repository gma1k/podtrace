package procmaps

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseLine_RealProcfsRoundTrip(t *testing.T) {
	data, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Skipf("cannot read own maps: %v", err)
	}

	named := 0
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		e, ok := ParseLine(line)
		if !ok {
			t.Fatalf("ParseLine rejected a live kernel line: %q", line)
		}
		if !strings.HasSuffix(line, e.Path) {
			t.Fatalf("path %q is not the tail of %q", e.Path, line)
		}
		if e.Named() && !e.Deleted {
			named++
			if !filepath.IsAbs(e.Path) {
				t.Errorf("named mapping has a relative path %q", e.Path)
			}
		}
	}
	if named == 0 {
		t.Fatal("no file-backed mappings parsed from live procfs")
	}
}
