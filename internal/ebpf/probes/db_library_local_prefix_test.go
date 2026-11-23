package probes

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindDBLibsInRootFindsAlpinePostgresLibpqUnderUsrLocal(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "usr", "local", "lib")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "libpq.so.5.14"), []byte("\x7fELF"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("libpq.so.5.14", filepath.Join(dir, "libpq.so.5")); err != nil {
		t.Fatal(err)
	}

	got := findDBLibsInRoot(root, []string{"libpq.so.5"})
	want := filepath.Join(dir, "libpq.so.5.14")
	if len(got) != 1 || got[0] != want {
		t.Errorf("findDBLibsInRoot = %v, want [%s]: the official postgres alpine images ship libpq there", got, want)
	}
}

func TestDBLibraryPathsCoverTheLocalPrefixLikeTheTLSSearch(t *testing.T) {
	paths := map[string]bool{}
	for _, p := range getArchitectureDBPaths([]string{"libhiredis.so.1"}) {
		paths[p] = true
	}
	for _, want := range []string{"/usr/local/lib/libhiredis.so.1", "/usr/local/lib64/libhiredis.so.1"} {
		if !paths[want] {
			t.Errorf("library search misses %s", want)
		}
	}
}
