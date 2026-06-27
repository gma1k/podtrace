package probes

import (
	"os"
	"runtime"
	"testing"
)

// TestGoSymbolFileOffset resolves a function from the test binary's own
// .gopclntab (the test binary is itself a Go ELF), validating the pclntab
// parse + vaddr→file-offset conversion without building a fixture.
func TestGoSymbolFileOffset(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ELF/.gopclntab parsing is Linux-only here")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot find test executable: %v", err)
	}

	off, ok := goSymbolFileOffset(exe, "runtime.main")
	if !ok {
		t.Fatal("expected to resolve runtime.main from .gopclntab")
	}
	if off == 0 {
		t.Errorf("resolved offset is 0, want a real file offset")
	}

	if _, ok := goSymbolFileOffset(exe, "definitely.NotAReal.Func"); ok {
		t.Error("expected not-found for a nonexistent symbol")
	}
}