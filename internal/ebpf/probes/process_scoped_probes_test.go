//go:build linux

package probes

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/gma1k/podtrace/internal/config"
)

func processScopedPrograms() *ebpf.Collection {
	return placeholderPrograms("uprobe_SSL_write", "uretprobe_SSL_write", "uprobe_SSL_read", "uretprobe_SSL_read",
		"uprobe_rustls_write", "uretprobe_rustls_write", "uprobe_rustls_read", "uretprobe_rustls_read",
		"uprobe_quiche_rs_send_request")
}

func TestAnotherProcessOfAStrippedBinaryGetsItsOwnFilteredProbes(t *testing.T) {
	const pid = 52401
	id := []byte{0x52, 0x40, 0x10, 0x01}
	root := strippedProcess(t, pid, id, true)
	placeDebugFile(t, root, id,
		namedAddress{"SSL_write", testTextVA + 0x10}, namedAddress{"SSL_read", testTextVA + 0x20},
		namedAddress{rustlsWriteSymbol, testTextVA + 0x30}, namedAddress{rustlsReadSymbol, testTextVA + 0x40},
		namedAddress{quicheSendSymbol, testTextVA + 0x50})
	f := installFakeAttacher(t, nil)

	links := AttachProcessScopedProbes(processScopedPrograms(), pid)
	if len(links) != 9 {
		t.Fatalf("%d links, want 4 SSL, 4 rustls and 1 quiche", len(links))
	}
	assertFilteredTo(t, f, pid, 9)
}

func TestAProcessWithoutADebugFileGetsNoProcessScopedProbes(t *testing.T) {
	const pid = 52402
	syntheticProc(t, pid, loadableRustSections(rustlsWriteSymbol, quicheSendSymbol))
	f := installFakeAttacher(t, nil)
	if links := AttachProcessScopedProbes(processScopedPrograms(), pid); len(links) != 0 || len(f.calls) != 0 {
		t.Fatalf("%d links, %d attaches for a binary whose probes are all shared", len(links), len(f.calls))
	}
}

func TestProcessScopedProbesSkipABinaryWithItsOwnSymbols(t *testing.T) {
	const pid = 52403
	id := []byte{0x52, 0x40, 0x30, 0x01}
	sections := append(loadableRustSections(rustlsWriteSymbol, rustlsReadSymbol, quicheSendSymbol),
		testSection{name: ".note.gnu.build-id", typ: shtNote, data: buildIDNote(id)})
	syntheticProc(t, pid, sections)
	placeDebugFile(t, filepath.Join(config.ProcBasePath, fmt.Sprint(pid), "root"), id,
		namedAddress{rustlsWriteSymbol, testTextVA + 0x30}, namedAddress{quicheSendSymbol, testTextVA + 0x50})
	f := installFakeAttacher(t, nil)
	if links := AttachProcessScopedProbes(processScopedPrograms(), pid); len(links) != 0 || len(f.calls) != 0 {
		t.Fatalf("%d links, %d attaches: the binary's own symbols already give shared probes", len(links), len(f.calls))
	}
}

func TestProcessScopedProbesNeedAProcessAndAnELF(t *testing.T) {
	coll := processScopedPrograms()
	if AttachProcessScopedProbes(coll, 0) != nil || AttachProcessScopedProbes(nil, 1) != nil {
		t.Error("a host-wide target or a missing collection got process-scoped probes")
	}
	syntheticProc(t, 52404, nil)
	if hasDebugFile(52499) {
		t.Error("a process without an executable has a debug file")
	}
	script := filepath.Join(config.ProcBasePath, "52405", "exe")
	if err := os.MkdirAll(filepath.Dir(script), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if hasDebugFile(52405) {
		t.Error("a script has a debug file")
	}
}
