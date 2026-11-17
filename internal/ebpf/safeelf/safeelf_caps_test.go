package safeelf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"testing"
)

func TestOpen_RealExecutable(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot find test executable: %v", err)
	}
	f, err := Open(exe)
	if err != nil {
		t.Fatalf("Open(%q) = %v, want a parsed ELF", exe, err)
	}
	if f == nil {
		t.Fatal("Open returned a nil file with no error")
		return
	}
	_ = f.Close()
}

func TestOpen_MissingFile(t *testing.T) {
	if _, err := Open("/no/such/podtrace/binary"); err == nil {
		t.Fatal("Open must return an error for a missing path")
	}
}

func TestSectionData_RejectsOversizedSection(t *testing.T) {
	sec := &elf.Section{SectionHeader: elf.SectionHeader{Name: ".huge", Size: MaxSectionSize + 1}}
	data, err := SectionData(sec)
	if err == nil {
		t.Fatal("SectionData must reject a section larger than MaxSectionSize")
	}
	if data != nil {
		t.Errorf("SectionData returned data %v alongside the cap error", data)
	}
}

func TestSectionData_ReadsRealSection(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot find test executable: %v", err)
	}
	f, err := Open(exe)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()

	sec := smallReadableSection(f)
	if sec == nil {
		t.Skip("no small in-file section available")
		return
	}
	data, err := SectionData(sec)
	if err != nil {
		t.Fatalf("SectionData(%q) = %v", sec.Name, err)
	}
	if uint64(len(data)) != sec.Size {
		t.Errorf("SectionData(%q) returned %d bytes, want %d", sec.Name, len(data), sec.Size)
	}
}

func TestSymbolTablesOfARealELFAreWithinCap(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot find test executable: %v", err)
	}
	f, err := Open(exe)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()

	if f.SectionByType(elf.SHT_SYMTAB) == nil {
		t.Skip("test binary has no symbol table to assert on")
	}
	if !SymbolTableWithinCap(f, elf.SHT_SYMTAB) || !SymbolTablesWithinCap(f) {
		t.Error("the test binary's symbol tables were judged too large")
	}
}

func TestDWARFWithinCap_OverCapIsRejected(t *testing.T) {
	f := &elf.File{Sections: []*elf.Section{
		{SectionHeader: elf.SectionHeader{Name: ".debug_info", Size: MaxDWARFTotalSize + 1}},
	}}
	if DWARFWithinCap(f) {
		t.Fatal("DWARFWithinCap must be false when combined DWARF exceeds MaxDWARFTotalSize")
	}
}

func TestDWARFWithinCap_CompressedPrefixCounts(t *testing.T) {
	f := &elf.File{Sections: []*elf.Section{
		{SectionHeader: elf.SectionHeader{Name: ".zdebug_info", Size: MaxDWARFTotalSize/2 + 1}},
		{SectionHeader: elf.SectionHeader{Name: ".zdebug_line", Size: MaxDWARFTotalSize/2 + 1}},
	}}
	if DWARFWithinCap(f) {
		t.Fatal("DWARFWithinCap must sum .zdebug_* sections toward the cap")
	}
}

func TestDWARFWithinCap_SmallSectionsWithinCap(t *testing.T) {
	f := &elf.File{Sections: []*elf.Section{
		{SectionHeader: elf.SectionHeader{Name: ".text", Size: 4096}},
		{SectionHeader: elf.SectionHeader{Name: ".debug_info", Size: 128}},
		{SectionHeader: elf.SectionHeader{Name: ".debug_line", Size: 64}},
	}}
	if !DWARFWithinCap(f) {
		t.Fatal("DWARFWithinCap must be true for small debug sections")
	}
}

func TestDWARFWithinCap_NoDebugSections(t *testing.T) {
	f := &elf.File{Sections: []*elf.Section{
		{SectionHeader: elf.SectionHeader{Name: ".text", Size: 4096}},
	}}
	if !DWARFWithinCap(f) {
		t.Fatal("DWARFWithinCap must be true when there are no debug sections")
	}
}

func TestRecoverParse_SwallowsPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("RecoverParse failed to contain the panic: %v", r)
		}
	}()
	parseThatPanics()
}

func parseThatPanics() {
	defer RecoverParse("test-parse")
	panic("malformed untrusted binary")
}

func smallReadableSection(f *elf.File) *elf.Section {
	for _, s := range f.Sections {
		if s.Type == elf.SHT_NOBITS {
			continue
		}
		if s.Size > 0 && s.Size < 1<<20 {
			return s
		}
	}
	return nil
}

func TestASymbolTableOverTheCapIsRejected(t *testing.T) {
	huge := &elf.File{Sections: []*elf.Section{
		{SectionHeader: elf.SectionHeader{Name: ".dynsym", Type: elf.SHT_DYNSYM, Size: 1024}},
		{SectionHeader: elf.SectionHeader{Name: ".symtab", Type: elf.SHT_SYMTAB, Size: MaxSymbolTableSize + 1, Link: 0}},
	}}
	if SymbolTablesWithinCap(huge) {
		t.Error("a .symtab over MaxSymbolTableSize passed; cilium would expand it to several times its size")
	}
	if SymbolTableWithinCap(huge, elf.SHT_SYMTAB) {
		t.Error("SymbolTableWithinCap passed a .symtab over MaxSymbolTableSize")
	}
	if !SymbolTablesWithinCap(&elf.File{}) {
		t.Error("a file without symbol tables was rejected")
	}
}

func zdebugHeader(declared uint64) []byte {
	header := []byte("ZLIB\x00\x00\x00\x00\x00\x00\x00\x00")
	binary.BigEndian.PutUint64(header[4:], declared)
	return header
}

func TestDWARFWithinCap_ZdebugDeclaredSizeCounts(t *testing.T) {
	f := &elf.File{Sections: []*elf.Section{
		{SectionHeader: elf.SectionHeader{Name: ".zdebug_info", Size: 600 << 10}, ReaderAt: bytes.NewReader(zdebugHeader(MaxDWARFTotalSize + 1))},
	}}
	if DWARFWithinCap(f) {
		t.Fatal("DWARFWithinCap must count the uncompressed size a .zdebug_* ZLIB header declares")
	}
}

func TestDWARFWithinCap_ZdebugDeclaredSizesSumWithoutOverflow(t *testing.T) {
	f := &elf.File{Sections: []*elf.Section{
		{SectionHeader: elf.SectionHeader{Name: ".debug_line", Size: 64}},
		{SectionHeader: elf.SectionHeader{Name: ".zdebug_info", Size: 32}, ReaderAt: bytes.NewReader(zdebugHeader(^uint64(0)))},
	}}
	if DWARFWithinCap(f) {
		t.Fatal("a declared size that wraps the running total must not pass")
	}
}

func TestDWARFWithinCap_SmallZdebugAndUnheaderedSectionsPass(t *testing.T) {
	f := &elf.File{Sections: []*elf.Section{
		{SectionHeader: elf.SectionHeader{Name: ".zdebug_info", Size: 32}, ReaderAt: bytes.NewReader(zdebugHeader(4096))},
		{SectionHeader: elf.SectionHeader{Name: ".zdebug_line", Size: 5}, ReaderAt: bytes.NewReader([]byte("plain"))},
		{SectionHeader: elf.SectionHeader{Name: ".zdebug_str", Type: elf.SHT_NOBITS, Size: 8}},
	}}
	if !DWARFWithinCap(f) {
		t.Fatal("small .zdebug_* sections must stay within the cap")
	}
}
