package ldsoconf

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/podtrace/podtrace/internal/config"
)

func withBase(t *testing.T, base string) {
	t.Helper()
	original := config.LdSoConfBasePath
	config.LdSoConfBasePath = base
	ResetForTesting()
	t.Cleanup(func() {
		config.LdSoConfBasePath = original
		ResetForTesting()
	})
}

func TestSearchPaths_ReadsRootConfAndConfD(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ld.so.conf"), []byte("/usr/local/lib\n# comment\n\n/opt/lib\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	confd := filepath.Join(dir, "ld.so.conf.d")
	if err := os.MkdirAll(confd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confd, "x86_64.conf"), []byte("/usr/lib/x86_64-linux-gnu\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confd, "ignored.txt"), []byte("/should/not/be/read\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	withBase(t, dir)

	got := SearchPaths()
	for _, want := range []string{"/usr/local/lib", "/opt/lib", "/usr/lib/x86_64-linux-gnu"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %q in %v", want, got)
		}
	}
	if slices.Contains(got, "/should/not/be/read") {
		t.Error("non-.conf files must be ignored")
	}
}

func TestSearchPaths_MissingDirsReturnEmpty(t *testing.T) {
	dir := t.TempDir() // empty
	withBase(t, dir)
	if got := SearchPaths(); len(got) != 0 {
		t.Errorf("empty base must yield 0 paths, got %v", got)
	}
}

func TestSearchPaths_BadBaseDirReturnsEmpty(t *testing.T) {
	withBase(t, "/non/existent/etc")
	if got := SearchPaths(); len(got) != 0 {
		t.Errorf("missing base must yield 0 paths, got %v", got)
	}
}
