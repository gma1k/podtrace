package probes

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"

	"github.com/gma1k/podtrace/internal/ebpf/safeelf"
	"github.com/gma1k/podtrace/internal/safeconv"
)

func allocatedBy(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return (after.TotalAlloc - before.TotalAlloc) >> 20
}

func patchFile(t *testing.T, path string, patch func([]byte)) {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	name := filepath.Base(path)
	raw, err := root.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	patch(raw)
	if err := root.WriteFile(name, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func dwarfUnit(abbrevOff uint32, dies []byte) []byte {
	out := binary.LittleEndian.AppendUint32(nil, safeconv.IntToUint32(7+len(dies)))
	out = binary.LittleEndian.AppendUint16(out, 4)
	out = binary.LittleEndian.AppendUint32(out, abbrevOff)
	out = append(out, 8)
	return append(out, dies...)
}

func writeDWARFELF(t *testing.T, abbrev, info []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dwarf")
	writeTestELF(t, path, []testSection{
		{name: ".text", typ: shtProgbits, flags: shfAlloc | shfExec, addr: testTextVA, data: make([]byte, 16)},
		{name: ".debug_abbrev", typ: shtProgbits, data: abbrev},
		{name: ".debug_info", typ: shtProgbits, data: info},
	})
	return path
}

const (
	nestedAbbrevCompileUnit = 1
	nestedAbbrevStruct      = 2
	nestedAbbrevParent      = 3
	nestedAbbrevBlock       = 4
	nestedAbbrevMember      = 5
)

func nestingAbbreviations() []byte {
	return []byte{
		nestedAbbrevCompileUnit, tagCompileUnit, 1, 0, 0,
		nestedAbbrevStruct, tagStructureType, 1, atName, formString, 0, 0,
		nestedAbbrevParent, tagMember, 1, atName, formString, 0, 0,
		nestedAbbrevBlock, 0x0b, 1, 0, 0,
		nestedAbbrevMember, tagMember, 0, atName, formString, atDataMemberLocation, formUdata, 0, 0,
		0,
	}
}

func TestDeeplyNestedChildrenOfAMemberDoNotOverflowTheStack(t *testing.T) {
	defer debug.SetMaxStack(debug.SetMaxStack(32 << 20))
	dies := []byte{nestedAbbrevCompileUnit, nestedAbbrevStruct}
	dies = append(dies, h3ServerRootType+"\x00"...)
	dies = append(dies, nestedAbbrevParent)
	dies = append(dies, "conn\x00"...)
	dies = append(dies, bytes.Repeat([]byte{nestedAbbrevBlock}, 1<<20)...)
	path := writeDWARFELF(t, nestingAbbreviations(), dwarfUnit(0, dies))

	if _, ok := resolveH3PeerPaths(path, 0, ""); ok {
		t.Fatal("resolved a peer path through a million nested entries")
	}
	d, closeFn, ok := openDWARF(path, 0)
	if !ok {
		t.Fatal("openDWARF failed on a small well-formed unit")
	}
	defer closeFn()
	if st := structByName(d, indexDWARFStructs(d), h3ServerRootType); st != nil {
		t.Fatalf("readStruct = %+v, want nil for a member nested past the depth cap", st)
	}
}

func TestAMemberWithNestedChildrenIsSkippedAndTheNextMemberRead(t *testing.T) {
	dies := []byte{nestedAbbrevCompileUnit, nestedAbbrevStruct}
	dies = append(dies, "pkg.T\x00"...)
	dies = append(dies, nestedAbbrevParent)
	dies = append(dies, "a\x00"...)
	dies = append(dies, nestedAbbrevBlock, nestedAbbrevBlock, 0, 0, 0)
	dies = append(dies, nestedAbbrevMember)
	dies = append(dies, "b\x00"...)
	dies = append(dies, 8, 0, 0)
	d, closeFn, ok := openDWARF(writeDWARFELF(t, nestingAbbreviations(), dwarfUnit(0, dies)), 0)
	if !ok {
		t.Fatal("openDWARF failed")
	}
	defer closeFn()
	st := structByName(d, indexDWARFStructs(d), "pkg.T")
	if st == nil || len(st.Field) != 2 || st.Field[0].Name != "a" || st.Field[1].Name != "b" || st.Field[1].ByteOffset != 8 {
		t.Fatalf("readStruct = %+v, want members a and b (offset 8)", st)
	}
}

func TestAStructWhoseMemberChildrenRunOffTheEndIsUnreadable(t *testing.T) {
	dies := []byte{nestedAbbrevCompileUnit, nestedAbbrevStruct}
	dies = append(dies, "pkg.T\x00"...)
	dies = append(dies, nestedAbbrevParent)
	dies = append(dies, "a\x00"...)
	dies = append(dies, nestedAbbrevBlock)
	d, closeFn, ok := openDWARF(writeDWARFELF(t, nestingAbbreviations(), dwarfUnit(0, dies)), 0)
	if !ok {
		t.Fatal("openDWARF failed")
	}
	defer closeFn()
	if st := structByName(d, indexDWARFStructs(d), "pkg.T"); st != nil {
		t.Fatalf("readStruct = %+v, want nil when the member's children never end", st)
	}
}

func TestASparseGosymtabIsNotParsed(t *testing.T) {
	const symtabSize = 8 << 20
	symtab := make([]byte, symtabSize)
	copy(symtab, []byte{0xfd, 0xff, 0xff, 0xff, 0, 0, 0, 8})
	path := filepath.Join(t.TempDir(), "gosymtab")
	writeTestELF(t, path, []testSection{
		{name: ".text", typ: shtProgbits, flags: shfAlloc | shfExec, addr: testTextVA, data: make([]byte, 64)},
		{name: ".gopclntab", typ: shtProgbits, flags: shfAlloc, data: pclnHeader(binary.LittleEndian, safeelf.Go120PCLNTabMagic, 8, 0, 128)},
		{name: ".gosymtab", typ: shtProgbits, flags: shfAlloc, data: symtab},
	})
	goBinaries.reset()
	t.Cleanup(goBinaries.reset)

	grew := allocatedBy(func() { _, _ = goSymbolFileOffset(path, "main.main") })
	if grew > 32 {
		t.Errorf("allocated %d MiB for a %d MiB .gosymtab of zeros, which decodes as one symbol per 3 bytes", grew, symtabSize>>20)
	}
}

func TestAPreGo12PclntabIsNotParsed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "go11")
	writeTestELF(t, path, []testSection{
		{name: ".text", typ: shtProgbits, flags: shfAlloc | shfExec, addr: testTextVA, data: make([]byte, 64)},
		{name: ".gopclntab", typ: shtProgbits, flags: shfAlloc, data: pclnHeader(binary.LittleEndian, 0x12345678, 8, 1, 128)},
	})
	if _, ok := parseGoBinary(path); ok {
		t.Fatal("parsed a .gopclntab without a Go 1.2+ header")
	}
}

func TestAHugeBuildInfoVersionLengthIsNotRead(t *testing.T) {
	const claimed = 64 << 20
	header := make([]byte, 32)
	copy(header, "\xff Go buildinf:")
	header[14], header[15] = 8, 2
	data := binary.AppendUvarint(header, claimed)
	data = append(data, "go1.26"...)
	path := filepath.Join(t.TempDir(), "buildinfo")
	writeTestELF(t, path, []testSection{
		{name: ".go.buildinfo", typ: shtProgbits, flags: shfAlloc, addr: 0x500000, data: data, load: true},
	})
	segmentSize := uint64(claimed + 4096)
	patchFile(t, path, func(raw []byte) {
		binary.LittleEndian.PutUint64(raw[64+32:], segmentSize)
		binary.LittleEndian.PutUint64(raw[64+40:], segmentSize)
	})
	if err := os.Truncate(path, int64(segmentSize)+(1<<20)); err != nil {
		t.Fatal(err)
	}

	var source string
	grew := allocatedBy(func() { _, source = h3OffsetsForGoVersion(path) })
	if source != "default" {
		t.Errorf("source = %.40q, want \"default\" for a version string claiming %d MiB", source, claimed>>20)
	}
	if grew > 8 {
		t.Errorf("allocated %d MiB reading a build info version string claiming %d MiB", grew, claimed>>20)
	}
}

func TestDebugRelocationsInAPositionIndependentExecutableAreNotRead(t *testing.T) {
	const relocations = 64 << 20
	var b dwarfBuilder
	quicServerDWARF(&b, false)
	path := filepath.Join(t.TempDir(), "pie")
	writeTestELF(t, path, []testSection{
		{name: ".debug_abbrev", typ: shtProgbits, data: dwarfAbbreviations()},
		{name: ".debug_info", typ: shtProgbits, data: b.info()},
		{name: ".rela.debug_info", typ: uint32(elf.SHT_RELA), info: 2, entsize: 24, declared: relocations},
	})
	patchFile(t, path, func(raw []byte) { binary.LittleEndian.PutUint16(raw[16:], uint16(elf.ET_DYN)) })
	if err := os.Truncate(path, relocations+(1<<20)); err != nil {
		t.Fatal(err)
	}

	var paths h3PeerPaths
	var ok bool
	grew := allocatedBy(func() {
		paths, ok = resolveH3PeerPaths(path, 0, "")
		_, _ = h3OffsetsFromDWARF(path, 0)
		_, _ = poolOffsetsFromDWARF(path, 0)
	})
	if !ok || paths.Server.NSteps != 3 {
		t.Errorf("resolveH3PeerPaths = (%+v, %v), want the 3-step server path read without relocations", paths, ok)
	}
	if grew > 16 {
		t.Errorf("allocated %d MiB beside a %d MiB .rela.debug_info that must not be read", grew, relocations>>20)
	}
}

func TestMillionsOfTinyDWARFUnitsAreRefused(t *testing.T) {
	const units = safeelf.MaxDWARFUnits * 4
	path := writeDWARFELF(t, dwarfAbbreviations(), bytes.Repeat(dwarfUnit(0, nil), units))
	var ok bool
	grew := allocatedBy(func() { _, ok = resolveH3PeerPaths(path, 0, "") })
	if ok {
		t.Fatal("resolved a peer path from units without entries")
	}
	if grew > 24 {
		t.Errorf("allocated %d MiB for %d empty 11-byte units", grew, units)
	}
}

func TestUnitsThatEachReparseOneAbbreviationTableAreRefused(t *testing.T) {
	const n = 1600
	var abbrev, info []byte
	for i := 1; i <= n; i++ {
		info = append(info, dwarfUnit(safeconv.IntToUint32(len(abbrev)), nil)...)
		abbrev = binary.AppendUvarint(abbrev, uint64(i))
		abbrev = append(abbrev, tagCompileUnit, 0, 0, 0)
	}
	path := writeDWARFELF(t, append(abbrev, 0), info)
	grew := allocatedBy(func() { _, _ = resolveH3PeerPaths(path, 0, "") })
	if grew > 16 {
		t.Errorf("allocated %d MiB for %d units naming offsets inside one %d-entry abbreviation table", grew, n, n)
	}
}

func entryStreamHash(t *testing.T, path string, load func(*elf.File) (int, uint64, error)) (int, uint64) {
	t.Helper()
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	n, h, err := load(f)
	if err != nil {
		t.Fatal(err)
	}
	return n, h
}

func TestDWARFReadsWhatTheStandardLibraryReadsFromAGoBinary(t *testing.T) {
	bin := goFixtureBinary(t)
	hashOf := func(f *elf.File, stdlib bool) (int, uint64, error) {
		d, err := f.DWARF()
		if !stdlib {
			d, err = safeelf.DWARF(f)
		}
		if err != nil {
			return 0, 0, err
		}
		h := fnv.New64a()
		r := d.Reader()
		n := 0
		for {
			e, err := r.Next()
			if err != nil || e == nil {
				return n, h.Sum64(), nil
			}
			n++
			_, _ = fmt.Fprintf(h, "%d %d %v|", e.Offset, e.Tag, e.Children)
			for _, field := range e.Field {
				_, _ = fmt.Fprintf(h, "%d=%v;", field.Attr, field.Val)
			}
		}
	}
	wantN, want := entryStreamHash(t, bin, func(f *elf.File) (int, uint64, error) { return hashOf(f, true) })
	gotN, got := entryStreamHash(t, bin, func(f *elf.File) (int, uint64, error) { return hashOf(f, false) })
	if gotN != wantN || got != want {
		t.Fatalf("read %d entries (%x), the standard library reads %d (%x)", gotN, got, wantN, want)
	}
}
