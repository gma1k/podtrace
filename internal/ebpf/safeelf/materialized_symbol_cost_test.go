package safeelf

import (
	"debug/elf"
	"testing"
)

func TestATableDeclaringMillionsOfTinySymbolsIsOverTheCapBeforeItIsRead(t *testing.T) {
	f := parseELF(t, elf.ELFCLASS64, sharedNameTable(2_700_000, 1))
	var within bool
	if mib := allocatedMiB(func() { within = SymbolTablesWithinCap(f) }); mib > 8 {
		t.Errorf("the check allocated %d MiB; the record count alone decides this table", mib)
	}
	if within || SymbolTableWithinCap(f, elf.SHT_SYMTAB) {
		t.Error("2.7M one-byte symbols passed; debug/elf and cilium would build over 400 MiB of records from them")
	}
}

func TestTablesWithinTheCapAloneCanBeOverItTogether(t *testing.T) {
	secs := sharedNameTable(400_000, 1)
	secs = append(secs, rawSection{name: ".dynsym", typ: elf.SHT_DYNSYM, link: 2, entsize: elf.Sym64Size, data: secs[0].data})
	f := parseELF(t, elf.ELFCLASS64, secs)
	if !SymbolTableWithinCap(f, elf.SHT_SYMTAB) || !SymbolTableWithinCap(f, elf.SHT_DYNSYM) {
		t.Fatal("a 400k-symbol table was rejected on its own")
	}
	if SymbolTablesWithinCap(f) {
		t.Error("two 400k-symbol tables passed together; cilium materialises both at once")
	}
}

func TestASmall32BitTableIsWithinTheCap(t *testing.T) {
	f := parseELF(t, elf.ELFCLASS32, symbolSections(elf.ELFCLASS32, elf.SHT_SYMTAB, testSymbol{name: "main", info: byte(elf.STT_FUNC)}))
	if !SymbolTableWithinCap(f, elf.SHT_SYMTAB) || !SymbolTablesWithinCap(f) {
		t.Error("a one-symbol 32-bit table was rejected")
	}
}
