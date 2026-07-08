package probes

import (
	"encoding/binary"
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
// directory, while a legitimate file inside it is still reachable.
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
