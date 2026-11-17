//go:build linux

package probes

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
)

const (
	rustlsReadSymbol = "_ZN6rustls4conn6Reader4read17h0000000000000000E"
	quicheSendSymbol = "_ZN6quiche2h310Connection12send_request17h0000000000000000E"
)

func strippedProcess(t *testing.T, pid uint32, id []byte, rust bool) string {
	t.Helper()
	secs := []testSection{
		{name: ".text", typ: shtProgbits, flags: shfAlloc | shfExec, addr: testTextVA, data: make([]byte, 0x100), load: true},
		{name: ".note.gnu.build-id", typ: shtNote, data: buildIDNote(id)},
	}
	if rust {
		secs = append(secs, testSection{name: ".comment", typ: shtProgbits, data: []byte("rustc version 1.90.0\x00")})
	}
	syntheticProc(t, pid, secs)
	return filepath.Join(config.ProcBasePath, fmt.Sprint(pid), "root")
}

func placeDebugFile(t *testing.T, root string, id []byte, syms ...namedAddress) {
	t.Helper()
	hexID := fmt.Sprintf("%x", id)
	secs := []testSection{{name: ".note.gnu.build-id", typ: shtNote, data: buildIDNote(id)}}
	writeTestELF(t, filepath.Join(root, "usr/lib/debug/.build-id", hexID[:2], hexID[2:]+".debug"), append(secs, functionSymtab(3, syms...)...))
}

func assertFilteredTo(t *testing.T, f *fakeAttacher, pid uint32, want int) {
	t.Helper()
	if len(f.calls) != want {
		t.Fatalf("%d attaches, want %d", len(f.calls), want)
	}
	for _, c := range f.calls {
		if c.pid != int(pid) {
			t.Errorf("uprobe at %#x has PID %d, want %d", c.addr, c.pid, pid)
		}
	}
}

func TestAStrippedTLSExecutableIsProbedOnlyInsideItsOwnProcess(t *testing.T) {
	const pid = 52201
	id := []byte{0x52, 0x20, 0x10, 0x01}
	root := strippedProcess(t, pid, id, false)
	placeDebugFile(t, root, id, namedAddress{"SSL_write", testTextVA + 0x10}, namedAddress{"SSL_read", testTextVA + 0x20})
	f := installFakeAttacher(t, nil)

	links := attachStrippedExecutableTLS(placeholderPrograms("uprobe_SSL_write", "uretprobe_SSL_write", "uprobe_SSL_read", "uretprobe_SSL_read"), pid)
	if len(links) != 4 {
		t.Fatalf("%d links, want 4", len(links))
	}
	assertFilteredTo(t, f, pid, 4)
}

func TestAStrippedTLSAttachSkipsAnExecutableThatExportsSSLOrIsMissing(t *testing.T) {
	const pid = 52202
	syntheticProc(t, pid, functionSymtab(2, namedAddress{"SSL_write", testTextVA}))
	f := installFakeAttacher(t, nil)
	coll := placeholderPrograms("uprobe_SSL_write")
	if links := attachStrippedExecutableTLS(coll, pid); len(links) != 0 || len(f.calls) != 0 {
		t.Errorf("an executable exporting SSL_write was probed by offset: %d links", len(links))
	}
	if links := attachStrippedExecutableTLS(coll, pid+1); len(links) != 0 {
		t.Errorf("a missing executable produced %d links", len(links))
	}
}

func TestStrippedRustlsIsProbedAtDebugFileOffsetsOnlyInsideItsProcess(t *testing.T) {
	const pid = 52203
	id := []byte{0x52, 0x20, 0x30, 0x01}
	root := strippedProcess(t, pid, id, true)
	placeDebugFile(t, root, id, namedAddress{rustlsWriteSymbol, testTextVA + 0x10}, namedAddress{rustlsReadSymbol, testTextVA + 0x20})
	f := installFakeAttacher(t, nil)

	links := AttachRustlsProbes(placeholderPrograms("uprobe_rustls_write", "uretprobe_rustls_write", "uprobe_rustls_read", "uretprobe_rustls_read"), pid)
	if len(links) != 4 {
		t.Fatalf("%d links, want 4", len(links))
	}
	assertFilteredTo(t, f, pid, 4)
}

func TestARustlsWriteWhoseReturnProbeFailsKeepsNoEntryProbe(t *testing.T) {
	const pid = 52204
	syntheticProc(t, pid, loadableRustSections(rustlsWriteSymbol))
	f := installFakeAttacher(t, func(c attachCall) error {
		if c.ret {
			return errors.New("uretprobe refused")
		}
		return nil
	})
	links := AttachRustlsProbes(placeholderPrograms("uprobe_rustls_write", "uretprobe_rustls_write", "uprobe_rustls_read", "uretprobe_rustls_read"), pid)
	if len(links) != 0 {
		t.Fatalf("%d links, want none when the write return probe cannot attach", len(links))
	}
	if len(f.links) != 1 || f.links[0].closed != 1 {
		t.Error("the write entry probe was left attached without its return probe")
	}
	for _, c := range f.calls {
		if c.pid != 0 {
			t.Errorf("a probe from the binary's own symbols was filtered to pid %d; it should be shared", c.pid)
		}
	}
}

func TestRustProbesNeedTheProcessExecutable(t *testing.T) {
	syntheticProc(t, 52205, rustLikeSections(rustlsWriteSymbol))
	coll := placeholderPrograms("uprobe_rustls_write", "uretprobe_rustls_write", "uprobe_rustls_read", "uretprobe_rustls_read", "uprobe_quiche_rs_send_request")
	if n := len(AttachRustlsProbes(coll, 52299)) + len(AttachQuicheRustProbes(coll, 52299)); n != 0 {
		t.Errorf("%d links for a process with no executable", n)
	}
}

func TestStrippedQuicheIsProbedAtDebugFileOffsetsOnlyInsideItsProcess(t *testing.T) {
	const pid = 52206
	id := []byte{0x52, 0x20, 0x60, 0x01}
	root := strippedProcess(t, pid, id, true)
	placeDebugFile(t, root, id, namedAddress{quicheSendSymbol, testTextVA + 0x30})
	f := installFakeAttacher(t, nil)

	if links := AttachQuicheRustProbes(placeholderPrograms("uprobe_quiche_rs_send_request"), pid); len(links) != 1 {
		t.Fatalf("%d links, want 1", len(links))
	}
	assertFilteredTo(t, f, pid, 1)
}
