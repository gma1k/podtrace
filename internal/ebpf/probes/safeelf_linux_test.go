//go:build linux

package probes

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// minimalELF64 returns the bytes of a valid, empty ELF64 executable header
// (no sections, no program headers) — enough for debug/elf.NewFile to parse.
func minimalELF64() []byte {
	b := make([]byte, 64)
	copy(b, []byte{0x7f, 'E', 'L', 'F'})
	b[4] = 2                                    // ELFCLASS64
	b[5] = 1                                    // ELFDATA2LSB
	b[6] = 1                                    // EV_CURRENT
	binary.LittleEndian.PutUint16(b[16:], 2)    // e_type = ET_EXEC
	binary.LittleEndian.PutUint16(b[18:], 0x3e) // e_machine = x86-64
	binary.LittleEndian.PutUint32(b[20:], 1)    // e_version
	binary.LittleEndian.PutUint16(b[52:], 64)   // e_ehsize
	return b
}

// TestOpenELFWithinRoot_ConfinesToRoot is the HS2 regression: a ".." or a
// symlink in the container-controlled debug path must not escape the confining
// directory, while a legitimate file inside it is still reachable. Linux-only
// because openELFWithinRoot uses openat2(RESOLVE_IN_ROOT).
func TestOpenELFWithinRoot_ConfinesToRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, minimalELF64(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "good.debug"), minimalELF64(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "escape.debug")); err != nil {
		t.Fatal(err)
	}

	t.Run("legit file inside root opens", func(t *testing.T) {
		f, err := openELFWithinRoot(root, "good.debug")
		if err != nil {
			t.Fatalf("expected to open a valid file inside root, got %v", err)
		}
		_ = f.Close()
	})
	t.Run("dotdot traversal blocked", func(t *testing.T) {
		if _, err := openELFWithinRoot(root, "../"+filepath.Base(outside)+"/secret"); err == nil {
			t.Error("openELFWithinRoot escaped root via ../ — must be blocked")
		}
	})
	t.Run("absolute path blocked", func(t *testing.T) {
		if _, err := openELFWithinRoot(root, secret); err == nil {
			t.Error("openELFWithinRoot followed an absolute path out of root")
		}
	})
	t.Run("symlink escape blocked", func(t *testing.T) {
		if _, err := openELFWithinRoot(root, "escape.debug"); err == nil {
			t.Error("openELFWithinRoot followed a symlink out of root — RESOLVE_IN_ROOT should block it")
		}
	})
}
