package filter

import "testing"

func TestSetCgroupPaths_OverwritesSinglePath(t *testing.T) {
	f := NewCgroupFilter()
	f.SetCgroupPath("/c/old")

	f.SetCgroupPaths([]string{"/c/a", "/c/b", "", "/c/c"})

	if f.cgroupPath != "" {
		t.Errorf("SetCgroupPaths should clear cgroupPath, got %q", f.cgroupPath)
	}
	if len(f.cgroupPaths) != 3 {
		t.Errorf("expected 3 paths (empty filtered), got %d: %+v", len(f.cgroupPaths), f.cgroupPaths)
	}
	for _, want := range []string{"/c/a", "/c/b", "/c/c"} {
		if _, ok := f.cgroupPaths[want]; !ok {
			t.Errorf("missing path %q", want)
		}
	}
}

func TestSetCgroupPaths_EmptyClearsExisting(t *testing.T) {
	f := NewCgroupFilter()
	f.SetCgroupPaths([]string{"/c/a"})
	if len(f.cgroupPaths) != 1 {
		t.Fatalf("setup failed: %v", f.cgroupPaths)
	}
	f.SetCgroupPaths(nil)
	if len(f.cgroupPaths) != 0 {
		t.Errorf("nil input should clear, got %v", f.cgroupPaths)
	}
}
