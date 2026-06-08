package procfs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadlink_Success(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	withProcBase(t, dir)

	got, err := Readlink("link")
	if err != nil {
		t.Fatalf("Readlink returned error: %v", err)
	}
	if got != target {
		t.Errorf("Readlink = %q, want %q", got, target)
	}
}

func TestReadlink_MissingLink(t *testing.T) {
	withProcBase(t, t.TempDir())
	if _, err := Readlink("does-not-exist"); err == nil {
		t.Fatal("expected error for missing link")
	}
}

func TestReadlink_RootOpenFails(t *testing.T) {
	withProcBase(t, "/no/such/proc/base")
	_, err := Readlink("self/exe")
	if err == nil {
		t.Fatal("expected error when root cannot be opened")
	}
	if !strings.Contains(err.Error(), "procfs") {
		t.Errorf("error should be wrapped with procfs prefix, got %v", err)
	}
}
