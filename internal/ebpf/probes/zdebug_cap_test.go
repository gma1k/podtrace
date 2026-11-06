package probes

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"path/filepath"
	"runtime"
	"testing"
)

func zdebugSection(t *testing.T, payload []byte, declared uint64) []byte {
	t.Helper()
	var out bytes.Buffer
	out.WriteString("ZLIB")
	_ = binary.Write(&out, binary.BigEndian, declared)
	w := zlib.NewWriter(&out)
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func quicServerZdebugELF(t *testing.T, infoDeclared func(actual uint64) uint64, info []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "zdebug")
	abbrev := dwarfAbbreviations()
	writeTestELF(t, path, []testSection{
		{name: ".text", typ: shtProgbits, flags: shfAlloc | shfExec, addr: testTextVA, data: make([]byte, 16)},
		{name: ".zdebug_abbrev", typ: shtProgbits, data: zdebugSection(t, abbrev, uint64(len(abbrev)))},
		{name: ".zdebug_info", typ: shtProgbits, data: zdebugSection(t, info, infoDeclared(uint64(len(info))))},
	})
	return path
}

func TestAZlibCompressedDebugSectionStillResolvesThePeerPath(t *testing.T) {
	var b dwarfBuilder
	quicServerDWARF(&b, false)
	path := quicServerZdebugELF(t, func(actual uint64) uint64 { return actual }, b.info())

	paths, ok := resolveH3PeerPaths(path, 0, "")
	if !ok || paths.Server.NSteps != 3 {
		t.Fatalf("resolveH3PeerPaths = (%+v, %v), want the 3-step server path from .zdebug_info", paths, ok)
	}
}

func TestAZlibBombDeclaredInADebugSectionIsRefusedBeforeInflating(t *testing.T) {
	const declared = 600 << 20
	path := quicServerZdebugELF(t, func(uint64) uint64 { return declared }, make([]byte, 8<<20))

	f, err := openELFCapped(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if dwarfWithinCap(f) {
		t.Fatalf("a .zdebug_info declaring %d MiB passed the DWARF cap", declared>>20)
	}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, ok := resolveH3PeerPaths(path, 0, "")
	_, _ = h3OffsetsFromDWARF(path, 0)
	_, _ = poolOffsetsFromDWARF(path, 0)
	runtime.ReadMemStats(&after)

	if ok {
		t.Error("resolved a peer path from a zlib bomb")
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<20 {
		t.Errorf("allocated %d MiB on a .zdebug_info declaring %d MiB", grew>>20, declared>>20)
	}
}
