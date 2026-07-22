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
	data := append([]byte("libfoo.so.debug"), 0, 0, 0xde, 0xad, 0xbe, 0xef)
	f, err := elfFromSections([]fixtureSection{{name: ".gnu_debuglink", typ: 1, data: data}})
	if err != nil {
		t.Fatal(err)
	}
	if got := debugLink(f); got != "libfoo.so.debug" {
		t.Errorf("debugLink = %q, want libfoo.so.debug", got)
	}
}

func TestDebugLinkAbsent(t *testing.T) {
	f, err := emptyELF()
	if err != nil {
		t.Fatal(err)
	}
	if got := debugLink(f); got != "" {
		t.Errorf("debugLink = %q, want empty when the section is absent", got)
	}
}

func TestSymbolVaddr(t *testing.T) {
	bin := goFixtureBinary(t)
	f, err := openELFCapped(bin)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer func() { _ = f.Close() }()

	vaddr, ok := symbolVaddr(f, "runtime.main")
	if !ok {
		t.Fatal("expected to resolve runtime.main from .symtab")
	}
	if vaddr == 0 {
		t.Error("runtime.main vaddr is 0")
	}
	if _, ok := symbolVaddr(f, "definitely_absent_symbol_zzz"); ok {
		t.Error("expected not-found for an absent symbol name")
	}
}
