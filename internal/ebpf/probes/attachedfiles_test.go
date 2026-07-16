package probes

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAttachedFiles_ClaimDedupesByInode: the same underlying library file is
// typically reached via different /proc/<pid>/root paths for different PIDs
// of one container, claims must dedupe on device+inode, not path string.
func TestAttachedFiles_ClaimDedupesByInode(t *testing.T) {
	dir := t.TempDir()
	lib := filepath.Join(dir, "libssl.so.3")
	if err := os.WriteFile(lib, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "libssl-alias.so.3")
	if err := os.Link(lib, alias); err != nil {
		t.Fatal(err)
	}

	af := NewAttachedFiles()
	if !af.Claim("tls", lib) {
		t.Fatal("first claim must succeed")
	}
	if af.Claim("tls", lib) {
		t.Error("second claim of the same path must be rejected")
	}
	if af.Claim("tls", alias) {
		t.Error("claim via a different path to the same file (same inode) must be rejected")
	}
	if !af.Claim("dns", lib) {
		t.Error("a different probe family must be able to claim the same file")
	}
}

func TestAttachedFiles_NilAndUnstatable(t *testing.T) {
	var af *AttachedFiles
	if !af.Claim("tls", "/nonexistent") {
		t.Error("nil AttachedFiles must always claim true")
	}
	af = NewAttachedFiles()
	for i := 0; i < 2; i++ {
		if !af.Claim("tls", "/nonexistent/path") {
			t.Errorf("claim %d of an unstatable path = false, want true (attach attempted, never silently skipped)", i+1)
		}
	}
}
