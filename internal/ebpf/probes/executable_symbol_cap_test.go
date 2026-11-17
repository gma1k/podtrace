//go:build linux

package probes

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestAByNameAttachIsRefusedForASymbolTableOfSharedLongNames(t *testing.T) {
	exe, err := openExecutable(sharedNameSymbolFile(t, 40000, 16<<10))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = exe.Close() }()
	var attachErr error
	if mib := mibAllocatedBy(func() { _, attachErr = exe.Uprobe("SSL_write", nil, nil) }); mib > 8 {
		t.Errorf("checking the symbol tables allocated %d MiB", mib)
	}
	if !errors.Is(attachErr, errSymbolTablesTooLarge) {
		t.Errorf("Uprobe = %v, want errSymbolTablesTooLarge before cilium copies 625 MiB of names", attachErr)
	}
}

func TestAFileThatIsNotELFHasNoBuildIDAndPassesTheSymbolCap(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "script"), []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open("script")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if id := buildIDOf(f); id != "" {
		t.Errorf("buildIDOf = %q, want empty", id)
	}
	if !symbolTablesWithinCap(f) {
		t.Error("a file that is not ELF was judged to have oversized symbol tables")
	}
}

func TestAnExecutableWithoutAFileHasNoPath(t *testing.T) {
	var none *executable
	if none.Path() != "" || (&executable{}).Path() != "" {
		t.Error("an executable without an open file reported a path")
	}
	exe, err := openExecutable(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = exe.Close() }()
	want := fmt.Sprintf("/proc/self/fd/%d", exe.file.Fd())
	if exe.Path() != want {
		t.Errorf("Path() = %q, want %q, the descriptor the executable holds", exe.Path(), want)
	}
}
