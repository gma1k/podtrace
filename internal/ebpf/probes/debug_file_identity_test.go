//go:build linux

package probes

import (
	"debug/elf"
	"encoding/binary"
	"hash/crc32"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func stringTableOffset(strtab []byte) uint32 {
	n := len(strtab)
	if n < 0 || n > math.MaxUint32 {
		panic("string table too large for a test fixture")
	}
	return uint32(n)
}

type namedAddress struct {
	name string
	addr uint64
}

func functionSymtab(strtabIndex uint32, syms ...namedAddress) []testSection {
	le := binary.LittleEndian
	strtab := []byte{0}
	symtab := make([]byte, 24)
	for _, s := range syms {
		e := make([]byte, 24)
		le.PutUint32(e[0:], stringTableOffset(strtab))
		e[4] = byte(elf.STT_FUNC)
		le.PutUint16(e[6:], 1)
		le.PutUint64(e[8:], s.addr)
		symtab = append(symtab, e...)
		strtab = append(strtab, s.name+"\x00"...)
	}
	return []testSection{
		{name: ".symtab", typ: shtSymtab, data: symtab, link: strtabIndex, entsize: 24},
		{name: ".strtab", typ: shtStrtab, data: strtab},
	}
}

func debugFileWithSSL(id []byte, write, read uint64) []testSection {
	secs := []testSection{{name: ".note.gnu.build-id", typ: shtNote, data: buildIDNote(id)}}
	return append(secs, functionSymtab(3, namedAddress{"SSL_write", write}, namedAddress{"SSL_read", read})...)
}

func strippedTarget(t *testing.T, path string, id []byte, extra ...testSection) *elf.File {
	t.Helper()
	secs := []testSection{{name: ".text", typ: shtProgbits, flags: shfAlloc | shfExec, addr: testTextVA, data: make([]byte, 0x100), load: true}}
	if id != nil {
		secs = append(secs, testSection{name: ".note.gnu.build-id", typ: shtNote, data: buildIDNote(id)})
	}
	writeTestELF(t, path, append(secs, extra...))
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestADebugFileCarryingTheTargetsBuildIDIsUsed(t *testing.T) {
	root := fakeTargetProcess(t, "52101", "/app/server")
	id := []byte{0xab, 0xcd, 0xef, 0x01}
	writeTestELF(t, filepath.Join(root, "usr/lib/debug/.build-id/ab/cdef01.debug"), debugFileWithSSL(id, testTextVA, testTextVA+0x10))
	target := strippedTarget(t, filepath.Join(t.TempDir(), "server"), id)

	dbg, source := openDebugInfo(target, 52101)
	if dbg == nil {
		t.Fatal("the matching debug file was not used")
	}
	_ = dbg.Close()
	if source != "debug-buildid" {
		t.Errorf("source = %q, want debug-buildid", source)
	}
}

func TestADebugFileForAnotherBuildIsRefused(t *testing.T) {
	root := fakeTargetProcess(t, "52102", "/app/server")
	writeTestELF(t, filepath.Join(root, "usr/lib/debug/.build-id/ab/cdef01.debug"), debugFileWithSSL([]byte{9, 9, 9, 9}, testTextVA, testTextVA+0x10))
	target := strippedTarget(t, filepath.Join(t.TempDir(), "server"), []byte{0xab, 0xcd, 0xef, 0x01})

	if dbg, _ := openDebugInfo(target, 52102); dbg != nil {
		_ = dbg.Close()
		t.Error("a debug file carrying another build-id was used")
	}
}

func TestADebugLinkFileMustCarryTheTargetsBuildIDWhenItHasOne(t *testing.T) {
	root := fakeTargetProcess(t, "52103", "/app/server")
	id := []byte{1, 2, 3, 4}
	link := testSection{name: ".gnu_debuglink", typ: shtProgbits, data: debugLinkSection("server.debug", 0)}
	target := strippedTarget(t, filepath.Join(t.TempDir(), "server"), id, link)

	writeTestELF(t, filepath.Join(root, "app/server.debug"), debugFileWithSSL([]byte{5, 6, 7, 8}, testTextVA, testTextVA))
	if dbg, _ := openDebugInfo(target, 52103); dbg != nil {
		_ = dbg.Close()
		t.Fatal("a debug-link file carrying another build-id was used")
	}
	writeTestELF(t, filepath.Join(root, "app/server.debug"), debugFileWithSSL(id, testTextVA, testTextVA))
	dbg, source := openDebugInfo(target, 52103)
	if dbg == nil || source != "debug-link" {
		t.Fatalf("the matching debug-link file was not used: source %q", source)
	}
	_ = dbg.Close()
}

func TestADebugLinkFileIsCheckedByItsCRCWhenTheTargetHasNoBuildID(t *testing.T) {
	root := fakeTargetProcess(t, "52104", "/app/server")
	writeTestELF(t, filepath.Join(root, "app/server.debug"), debugFileWithSSL([]byte{1}, testTextVA, testTextVA))
	rootfs, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rootfs.Close() }()
	content, err := rootfs.ReadFile("app/server.debug")
	if err != nil {
		t.Fatal(err)
	}
	for crc, wantFound := range map[uint32]bool{crc32.ChecksumIEEE(content): true, crc32.ChecksumIEEE(content) + 1: false} {
		link := testSection{name: ".gnu_debuglink", typ: shtProgbits, data: debugLinkSection("server.debug", crc)}
		target := strippedTarget(t, filepath.Join(t.TempDir(), "server"), nil, link)
		dbg, _ := openDebugInfo(target, 52104)
		if (dbg != nil) != wantFound {
			t.Errorf("crc %#x: found = %v, want %v", crc, dbg != nil, wantFound)
		}
		if dbg != nil {
			_ = dbg.Close()
		}
	}
}

func TestADebugLinkWithoutACRCOrBuildIDIsNotFollowed(t *testing.T) {
	root := fakeTargetProcess(t, "52105", "/app/server")
	writeTestELF(t, filepath.Join(root, "app/server.debug"), debugFileWithSSL([]byte{1}, testTextVA, testTextVA))
	link := testSection{name: ".gnu_debuglink", typ: shtProgbits, data: []byte("server.debug\x00")}
	target := strippedTarget(t, filepath.Join(t.TempDir(), "server"), nil, link)
	if dbg, _ := openDebugInfo(target, 52105); dbg != nil {
		_ = dbg.Close()
		t.Error("a debug link with nothing to verify the file by was followed")
	}
}

func TestAHugeBuildIDNoteIsIgnoredWithoutBeingRead(t *testing.T) {
	f := &elf.File{Sections: []*elf.Section{{SectionHeader: elf.SectionHeader{Name: ".note.gnu.build-id", Type: elf.SHT_NOTE, Size: 500 << 20}}}}
	if id := elfBuildID(f); id != "" {
		t.Errorf("elfBuildID = %q, want empty for a 500 MiB note", id)
	}
	big := &elf.File{Sections: []*elf.Section{{SectionHeader: elf.SectionHeader{Name: ".gnu_debuglink", Type: elf.SHT_PROGBITS, Size: 1 << 20}}}}
	if name, _, _ := debugLink(big); name != "" {
		t.Errorf("debugLink = %q, want empty for a 1 MiB section", name)
	}
}

func TestStrippedTLSOffsetsComeFromTheVerifiedDebugFile(t *testing.T) {
	root := fakeTargetProcess(t, "52106", "/app/server")
	id := []byte{0xab, 0xcd, 0xef, 0x02}
	writeTestELF(t, filepath.Join(root, "usr/lib/debug/.build-id/ab/cdef02.debug"), debugFileWithSSL(id, testTextVA+0x10, testTextVA+0x20))
	exe := filepath.Join(t.TempDir(), "server")
	text := strippedTarget(t, exe, id).Section(".text").Offset

	off, ok := resolveSSLOffsets(exe, 52106)
	if !ok {
		t.Fatal("no offsets resolved from the matching debug file")
	}
	if off.write != text+0x10 || off.read != text+0x20 || off.source != "debug-buildid" {
		t.Errorf("offsets = %+v, want write %#x read %#x from debug-buildid", off, text+0x10, text+0x20)
	}
}

func TestStrippedTLSOffsetsOutsideTheTargetsCodeAreRefused(t *testing.T) {
	root := fakeTargetProcess(t, "52107", "/app/server")
	id := []byte{0xab, 0xcd, 0xef, 0x03}
	writeTestELF(t, filepath.Join(root, "usr/lib/debug/.build-id/ab/cdef03.debug"), debugFileWithSSL(id, testTextVA+0x10, testTextVA+0x100000))
	exe := filepath.Join(t.TempDir(), "server")
	strippedTarget(t, exe, id)

	if off, ok := resolveSSLOffsets(exe, 52107); ok {
		t.Errorf("resolved %+v for a symbol outside every executable segment", off)
	}
}

func TestADebugFileThatCannotBeReadFailsItsCRCCheck(t *testing.T) {
	f := openTestBinary(t)
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if crcMatches(0)(f, fi, nil) {
		t.Error("an unreadable debug file passed the CRC check")
	}
}

func openTestBinary(t *testing.T) *os.File {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.OpenRoot(filepath.Dir(self))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	f, err := dir.Open(filepath.Base(self))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}
