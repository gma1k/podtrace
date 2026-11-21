//go:build linux

package probes

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
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

func TestAByNameAttachIsRefusedForMillionsOfTinySymbols(t *testing.T) {
	exe, err := openExecutable(sharedNameSymbolFile(t, 2_700_000, 1))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = exe.Close() }()
	var attachErr error
	if mib := mibAllocatedBy(func() { _, attachErr = exe.Uprobe("SSL_write", nil, nil) }); mib > 8 {
		t.Errorf("checking the symbol tables allocated %d MiB", mib)
	}
	if !errors.Is(attachErr, errSymbolTablesTooLarge) {
		t.Errorf("Uprobe = %v, want errSymbolTablesTooLarge before cilium builds 400 MiB of symbol records", attachErr)
	}
}

func TestALibraryOverTheSymbolCapIsReportedOnceAndSkipped(t *testing.T) {
	var warned []string
	orig := warnTLSLibrarySkipped
	warnTLSLibrarySkipped = func(lib string, _ uint32) { warned = append(warned, lib) }
	t.Cleanup(func() { warnTLSLibrarySkipped = orig })

	hostile, err := openExecutable(sharedNameSymbolFile(t, 2_700_000, 1))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hostile.Close() }()
	if tlsLibraryResolvable(hostile, "/hostile/libssl.so.3", 7) {
		t.Error("a library over the symbol cap was judged resolvable")
	}
	small, err := openExecutable(sharedNameSymbolFile(t, 10, 4))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = small.Close() }()
	if !tlsLibraryResolvable(small, "/usr/lib/libssl.so.3", 7) {
		t.Error("a small library was refused")
	}
	if len(warned) != 1 || warned[0] != "/hostile/libssl.so.3" {
		t.Errorf("warned about %v, want only the oversized library", warned)
	}
}

func TestTheDefaultSkipWarningLogsWithoutPanicking(t *testing.T) {
	warnTLSLibrarySkipped("/hostile/libssl.so.3", 7)
}

func TestAnOversizedLibsslIsSkippedWholeByTheTLSAttach(t *testing.T) {
	const pid = 4402
	syntheticProc(t, pid, rustLikeSections("f"))
	hostile, err := os.ReadFile(sharedNameSymbolFile(t, 2_700_000, 1))
	if err != nil {
		t.Fatal(err)
	}
	lib := filepath.Join(config.ProcBasePath, "4402", "root", "usr/lib/libssl.so.3")
	if err := os.MkdirAll(filepath.Dir(lib), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lib, hostile, 0o600); err != nil {
		t.Fatal(err)
	}
	var warned []string
	orig := warnTLSLibrarySkipped
	warnTLSLibrarySkipped = func(lib string, _ uint32) { warned = append(warned, lib) }
	t.Cleanup(func() { warnTLSLibrarySkipped = orig })
	coll := placeholderPrograms("uprobe_SSL_write", "uretprobe_SSL_write", "uprobe_SSL_read", "uretprobe_SSL_read")
	f := installFakeAttacher(t, func(attachCall) error { return nil })

	AttachTLSProbesWithPID(coll, "", pid, nil)

	if len(f.calls) != 0 {
		t.Errorf("attached %d probes to a library whose symbols cannot be resolved safely", len(f.calls))
	}
	if len(warned) != 1 {
		t.Errorf("warned %d times, want once for the library", len(warned))
	}
}
