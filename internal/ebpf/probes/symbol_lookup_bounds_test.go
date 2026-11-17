//go:build linux

package probes

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"path/filepath"
	"runtime"
	"testing"
)

func sharedNameSymbolFile(t *testing.T, symbols, nameLen int) string {
	t.Helper()
	le := binary.LittleEndian
	strtab := append([]byte{0}, append(bytes.Repeat([]byte{'A'}, nameLen), 0)...)
	table := make([]byte, 24*(symbols+1))
	for i := 1; i <= symbols; i++ {
		e := table[i*24:]
		le.PutUint32(e[0:], 1)
		e[4] = byte(elf.STT_FUNC)
		le.PutUint64(e[8:], testTextVA)
	}
	path := filepath.Join(t.TempDir(), "hostile")
	writeTestELF(t, path, []testSection{
		{name: ".hidden", typ: shtSymtab, link: 2, entsize: 24, data: table},
		{name: ".strtab", typ: shtStrtab, data: strtab},
		{name: ".symtab", typ: shtProgbits, data: make([]byte, 24)},
	})
	return path
}

func mibAllocatedBy(f func()) uint64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return (after.TotalAlloc - before.TotalAlloc) >> 20
}

func TestSymbolLookupsDoNotCopyAName(t *testing.T) {
	f, err := openELFCapped(sharedNameSymbolFile(t, 40000, 16<<10))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	for name, lookup := range map[string]func(){
		"symbolVaddr":           func() { _, _ = symbolVaddr(f, "SSL_write") },
		"hasSymbolNamed":        func() { _ = hasSymbolNamed(f, "SSL_write") },
		"findSymbolsContaining": func() { _ = findSymbolsContaining(f, 4, "rustls", "Writer") },
	} {
		if mib := mibAllocatedBy(lookup); mib > 8 {
			t.Errorf("%s allocated %d MiB over 40000 symbols sharing a 16 KiB name", name, mib)
		}
	}
}

func TestSymbolLookupsReadBothTables(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lib")
	secs := functionSymtab(2, namedAddress{"local_fn", testTextVA}, namedAddress{"undefined_fn", 0})
	dyn := functionSymtab(4, namedAddress{"SSL_write", testTextVA + 0x40})
	dyn[0].name, dyn[0].typ = ".dynsym", uint32(elf.SHT_DYNSYM)
	dyn[1].name = ".dynstr"
	writeTestELF(t, path, append(secs, dyn...))
	f, err := openELFCapped(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	if v, ok := symbolVaddr(f, "SSL_write"); !ok || v != testTextVA+0x40 {
		t.Errorf("symbolVaddr(SSL_write) = (%#x, %v), want the .dynsym value", v, ok)
	}
	if _, ok := symbolVaddr(f, "undefined_fn"); ok {
		t.Error("symbolVaddr returned an undefined symbol")
	}
	if !hasSymbolNamed(f, "SSL_write") || !hasSymbolNamed(f, "undefined_fn") || hasSymbolNamed(f, "absent") {
		t.Error("hasSymbolNamed did not report exactly the names either table carries")
	}
	if got := findSymbolsContaining(f, 4, "fn"); len(got) != 1 || got[0] != testTextVA {
		t.Errorf("findSymbolsContaining = %#x, want only the defined function", got)
	}
	if _, ok := findSymbolContaining(f, "absent"); ok {
		t.Error("findSymbolContaining found an absent symbol")
	}
}

func TestCodeOffsetsMustLieInTheFileBackedPartOfAnExecutableSegment(t *testing.T) {
	f := &elf.File{Progs: []*elf.Prog{
		{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R, Off: 0, Vaddr: 0x400000, Filesz: 0x1000, Memsz: 0x1000}},
		{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X, Off: 0x1000, Vaddr: 0x401000, Filesz: 0x100, Memsz: 0x2000}},
		{ProgHeader: elf.ProgHeader{Type: elf.PT_NOTE, Flags: elf.PF_X, Off: 0x3000, Vaddr: 0x500000, Filesz: 0x100, Memsz: 0x100}},
	}}
	if off, ok := codeFileOffset(f, 0x401010); !ok || off != 0x1010 {
		t.Errorf("codeFileOffset(text) = (%#x, %v), want 0x1010", off, ok)
	}
	for _, vaddr := range []uint64{0x400010, 0x401100, 0x500010, 0x3ff000} {
		if off, ok := codeFileOffset(f, vaddr); ok {
			t.Errorf("codeFileOffset(%#x) = %#x, want a refusal", vaddr, off)
		}
	}
}
