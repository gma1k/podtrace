package safeelf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"testing"
)

func collectSymbols(t *testing.T, f *elf.File, typ elf.SectionType) map[string]Symbol {
	t.Helper()
	got := map[string]Symbol{}
	if err := ForEachSymbol(f, typ, func(name []byte, sym Symbol) bool {
		got[string(name)] = sym
		return true
	}); err != nil {
		t.Fatalf("ForEachSymbol: %v", err)
	}
	return got
}

func TestForEachSymbolReadsBothELFClasses(t *testing.T) {
	for _, class := range []elf.Class{elf.ELFCLASS64, elf.ELFCLASS32} {
		f := parseELF(t, class, symbolSections(class, elf.SHT_SYMTAB,
			testSymbol{name: "SSL_write", info: byte(elf.STT_FUNC), value: 0x1000},
			testSymbol{name: "SSL_read", info: byte(elf.STT_FUNC), value: 0x2000}))
		got := collectSymbols(t, f, elf.SHT_SYMTAB)
		if got["SSL_write"].Value != 0x1000 || got["SSL_read"].Value != 0x2000 {
			t.Errorf("%v: symbols = %+v", class, got)
		}
		if elf.ST_TYPE(got["SSL_write"].Info) != elf.STT_FUNC || got["SSL_write"].Section != 1 || got["SSL_write"].Size != 16 {
			t.Errorf("%v: SSL_write = %+v", class, got["SSL_write"])
		}
		if _, ok := got[""]; ok {
			t.Errorf("%v: the reserved null entry was reported", class)
		}
	}
}

func TestForEachSymbolStopsWhenTheCallbackSaysSo(t *testing.T) {
	f := parseELF(t, elf.ELFCLASS64, symbolSections(elf.ELFCLASS64, elf.SHT_SYMTAB,
		testSymbol{name: "a"}, testSymbol{name: "b"}, testSymbol{name: "c"}))
	calls := 0
	if err := ForEachSymbol(f, elf.SHT_SYMTAB, func([]byte, Symbol) bool {
		calls++
		return false
	}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("callback ran %d times after returning false, want 1", calls)
	}
}

func TestForEachSymbolFindsTheTableByTypeNotByName(t *testing.T) {
	secs := symbolSections(elf.ELFCLASS64, elf.SHT_SYMTAB, testSymbol{name: "hidden", value: 0x10})
	secs = append(secs, rawSection{name: ".symtab", typ: elf.SHT_PROGBITS, data: make([]byte, elf.Sym64Size)})
	f := parseELF(t, elf.ELFCLASS64, secs)
	if _, ok := collectSymbols(t, f, elf.SHT_SYMTAB)["hidden"]; !ok {
		t.Error("the SHT_SYMTAB section debug/elf parses was not the one walked")
	}
}

func TestForEachSymbolWithoutATableReportsNoSymbols(t *testing.T) {
	f := parseELF(t, elf.ELFCLASS64, nil)
	if err := ForEachSymbol(f, elf.SHT_DYNSYM, func([]byte, Symbol) bool { return true }); !errors.Is(err, elf.ErrNoSymbols) {
		t.Errorf("err = %v, want elf.ErrNoSymbols", err)
	}
}

func TestForEachSymbolRefusesMalformedTables(t *testing.T) {
	badLink := symbolSections(elf.ELFCLASS64, elf.SHT_SYMTAB, testSymbol{name: "x"})
	badLink[0].link = 99
	ragged := symbolSections(elf.ELFCLASS64, elf.SHT_SYMTAB, testSymbol{name: "x"})
	ragged[0].data = append(ragged[0].data, 0)
	for name, secs := range map[string][]rawSection{"invalid link": badLink, "ragged table": ragged} {
		f := parseELF(t, elf.ELFCLASS64, secs)
		if err := ForEachSymbol(f, elf.SHT_SYMTAB, func([]byte, Symbol) bool { return true }); err == nil {
			t.Errorf("%s: ForEachSymbol accepted the table", name)
		}
	}
}

func TestForEachSymbolRefusesAnUnknownClass(t *testing.T) {
	f := parseELF(t, elf.ELFCLASS64, symbolSections(elf.ELFCLASS64, elf.SHT_SYMTAB, testSymbol{name: "x"}))
	f.Class = elf.ELFCLASSNONE
	if err := ForEachSymbol(f, elf.SHT_SYMTAB, func([]byte, Symbol) bool { return true }); err == nil {
		t.Error("ForEachSymbol walked a table of unknown class")
	}
}

func TestSymbolNamesOutsideTheStringTableAreEmpty(t *testing.T) {
	strs := []byte("\x00abc\x00def")
	if got := symbolName(strs, 1); string(got) != "abc" {
		t.Errorf("symbolName(1) = %q, want abc", got)
	}
	if got := symbolName(strs, 5); got != nil {
		t.Errorf("an unterminated name = %q, want nil", got)
	}
	if got := symbolName(strs, 100); got != nil {
		t.Errorf("an out-of-range name = %q, want nil", got)
	}
}

func sharedNameTable(symbols int, nameLen int) []rawSection {
	le := binary.LittleEndian
	strtab := append([]byte{0}, append(bytes.Repeat([]byte{'A'}, nameLen), 0)...)
	table := make([]byte, elf.Sym64Size*(symbols+1))
	for i := 1; i <= symbols; i++ {
		e := table[i*elf.Sym64Size:]
		le.PutUint32(e[0:], 1)
		e[4] = byte(elf.STT_FUNC)
		le.PutUint64(e[8:], 0x1000)
	}
	return []rawSection{
		{name: ".hidden", typ: elf.SHT_SYMTAB, link: 2, entsize: elf.Sym64Size, data: table},
		{name: ".strtab", typ: elf.SHT_STRTAB, data: strtab},
		{name: ".symtab", typ: elf.SHT_PROGBITS, data: make([]byte, elf.Sym64Size)},
	}
}

func TestATableNamingEverySymbolWithOneLongStringIsOverTheCap(t *testing.T) {
	f := parseELF(t, elf.ELFCLASS64, sharedNameTable(40000, 16<<10))
	var within bool
	if mib := allocatedMiB(func() { within = SymbolTableWithinCap(f, elf.SHT_SYMTAB) }); mib > 8 {
		t.Errorf("the check itself allocated %d MiB", mib)
	}
	if within || SymbolTablesWithinCap(f) {
		t.Error("40000 symbols sharing a 16 KiB name passed; debug/elf would copy 625 MiB of names")
	}
	if mib := allocatedMiB(func() {
		_ = ForEachSymbol(f, elf.SHT_SYMTAB, func([]byte, Symbol) bool { return true })
	}); mib > 8 {
		t.Errorf("walking the table allocated %d MiB; names must not be copied", mib)
	}
}

func TestACompressedOrOversizedSymbolTableIsOverTheCap(t *testing.T) {
	compressed := symbolSections(elf.ELFCLASS64, elf.SHT_SYMTAB, testSymbol{name: "x"})
	compressed[0].flags = elf.SHF_COMPRESSED
	zdebugNamed := symbolSections(elf.ELFCLASS64, elf.SHT_SYMTAB, testSymbol{name: "x"})
	zdebugNamed[1].name = ".zdebug_str"
	hugeStrings := symbolSections(elf.ELFCLASS64, elf.SHT_SYMTAB, testSymbol{name: "x"})
	hugeStrings[1].declared = MaxSymbolTableSize + 1
	for name, secs := range map[string][]rawSection{
		"compressed table": compressed, ".zdebug string table": zdebugNamed, "oversized string table": hugeStrings,
	} {
		f := parseELF(t, elf.ELFCLASS64, secs)
		if SymbolTableWithinCap(f, elf.SHT_SYMTAB) {
			t.Errorf("%s passed the cap", name)
		}
		if err := ForEachSymbol(f, elf.SHT_SYMTAB, func([]byte, Symbol) bool { return true }); !errors.Is(err, ErrSymbolTableTooLarge) {
			t.Errorf("%s: ForEachSymbol err = %v, want ErrSymbolTableTooLarge", name, err)
		}
	}
}

func TestAnOversizedVersionSectionPutsTheDynamicTableOverTheCap(t *testing.T) {
	secs := symbolSections(elf.ELFCLASS64, elf.SHT_DYNSYM, testSymbol{name: "SSL_write"})
	if f := parseELF(t, elf.ELFCLASS64, secs); !SymbolTableWithinCap(f, elf.SHT_DYNSYM) {
		t.Fatal("a small dynamic table was rejected")
	}
	secs = append(secs, rawSection{name: ".gnu.version", typ: elf.SHT_GNU_VERSYM, declared: MaxSymbolTableSize + 1})
	if f := parseELF(t, elf.ELFCLASS64, secs); SymbolTableWithinCap(f, elf.SHT_DYNSYM) {
		t.Error("an oversized .gnu.version passed; DynamicSymbols reads it whole")
	}
}
