package safeelf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSafeDebugName(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"libfoo.so.debug", true},
		{"my-app.debug", true},
		{"", false},
		{".", false},
		{"..", false},
		{"../../../proc/kcore", false},
		{"/etc/shadow", false},
		{"a/b.debug", false},
		{"a\x00b", false},
	}
	for _, tc := range cases {
		if got := SafeDebugName(tc.in); got != tc.want {
			t.Errorf("SafeDebugName(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestOpen_RejectsOversized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "huge")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxFileSize + 1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	if _, err := Open(path); err == nil {
		t.Fatal("Open must reject a file larger than MaxFileSize")
	}
}

func TestSectionData_NilSection(t *testing.T) {
	data, err := SectionData(nil)
	if err != nil || data != nil {
		t.Errorf("SectionData(nil) = (%v, %v), want (nil, nil)", data, err)
	}
}
