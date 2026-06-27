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

func TestGoFuncReturnOffsets(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("x86-64 disassembly only")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot find test executable: %v", err)
	}

	entryOff, retOffs, ok := goFuncReturnOffsets(exe, "runtime.main")
	if !ok {
		t.Fatal("expected to resolve runtime.main return sites")
	}
	if entryOff == 0 {
		t.Error("entry offset is 0")
	}
	if len(retOffs) == 0 {
		t.Fatal("expected at least one RET site")
	}
	for _, ro := range retOffs {
		if ro <= entryOff {
			t.Errorf("RET offset %#x not after entry %#x", ro, entryOff)
		}
	}

	if _, _, ok := goFuncReturnOffsets(exe, "definitely.NotAReal.Func"); ok {
		t.Error("expected not-found for a nonexistent symbol")
	}
}
