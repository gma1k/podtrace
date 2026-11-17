package safeelf

import (
	"debug/elf"
	"os"
	"testing"
)

func TestACheckOnAClosedFileFails(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err := checkRegular(f, f.Name()); err == nil {
		t.Error("a closed file passed the regular-file check")
	}
}

func TestASymbolTableRunningPastTheFileIsRefused(t *testing.T) {
	shortTable := symbolSections(elf.ELFCLASS64, elf.SHT_SYMTAB, testSymbol{name: "x"})
	shortTable[0].declared = 1 << 20
	shortStrings := symbolSections(elf.ELFCLASS64, elf.SHT_SYMTAB, testSymbol{name: "x"})
	shortStrings[1].declared = 1 << 20
	for name, secs := range map[string][]rawSection{"symbol table": shortTable, "string table": shortStrings} {
		f := parseELF(t, elf.ELFCLASS64, secs)
		if err := ForEachSymbol(f, elf.SHT_SYMTAB, func([]byte, Symbol) bool { return true }); err == nil {
			t.Errorf("a %s running past the end of the file was walked", name)
		}
	}
}
