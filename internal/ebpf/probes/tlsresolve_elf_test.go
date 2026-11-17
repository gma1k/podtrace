package probes

import (
	"encoding/hex"
	"os"
	"runtime"
	"testing"
)

func TestElfBuildIDRealBinary(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses the test binary's .note.gnu.build-id")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot find test executable: %v", err)
	}
	f, err := openELFCapped(exe)
	if err != nil {
		t.Skipf("cannot open test executable: %v", err)
	}
	defer func() { _ = f.Close() }()

	if f.Section(".note.gnu.build-id") == nil {
		t.Skip("test binary has no GNU build-id note")
	}
	id := elfBuildID(f)
	if len(id) == 0 {
		t.Fatal("expected a non-empty build-id from a note-bearing binary")
	}
	if _, err := hex.DecodeString(id); err != nil {
		t.Errorf("build-id %q is not valid lowercase hex: %v", id, err)
	}
}

func TestElfBuildIDNoNote(t *testing.T) {
	f, err := emptyELF()
	if err != nil {
		t.Fatal(err)
	}
	if id := elfBuildID(f); id != "" {
		t.Errorf("expected empty build-id when the note is absent, got %q", id)
	}
}

func TestDebugLink(t *testing.T) {
	data := append([]byte("libfoo.so.debug"), 0, 0xef, 0xbe, 0xad, 0xde)
	f, err := elfFromSections([]fixtureSection{{name: ".gnu_debuglink", typ: 1, data: data}})
	if err != nil {
		t.Fatal(err)
	}
	name, crc, hasCRC := debugLink(f)
	if name != "libfoo.so.debug" || !hasCRC || crc != 0xdeadbeef {
		t.Errorf("debugLink = (%q, %#x, %v), want (libfoo.so.debug, 0xdeadbeef, true)", name, crc, hasCRC)
	}
}

func TestDebugLinkWithoutItsCRCKeepsTheName(t *testing.T) {
	f, err := elfFromSections([]fixtureSection{{name: ".gnu_debuglink", typ: 1, data: []byte("app.debug\x00")}})
	if err != nil {
		t.Fatal(err)
	}
	if name, _, hasCRC := debugLink(f); name != "app.debug" || hasCRC {
		t.Errorf("debugLink = (%q, hasCRC %v), want (app.debug, false)", name, hasCRC)
	}
}

func TestDebugLinkAbsent(t *testing.T) {
	f, err := emptyELF()
	if err != nil {
		t.Fatal(err)
	}
	if name, _, _ := debugLink(f); name != "" {
		t.Errorf("debugLink = %q, want empty when the section is absent", name)
	}
}
