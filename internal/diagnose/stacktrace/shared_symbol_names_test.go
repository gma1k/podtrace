package stacktrace

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"math"
	"runtime"
	"testing"
	"unsafe"
)

func fileOffset(n int) uint64 {
	if n < 0 {
		panic("negative offset")
	}
	return uint64(n)
}

func sectionCount(n int) uint16 {
	if n < 0 || n > math.MaxUint16 {
		panic("section count out of range")
	}
	return uint16(n)
}

func sharedNameELF(symbols, nameLen int) []byte {
	le := binary.LittleEndian
	strtab := append([]byte{0}, append(bytes.Repeat([]byte{'A'}, nameLen), 0)...)
	symtab := make([]byte, elf.Sym64Size*(symbols+1))
	for i := 1; i <= symbols; i++ {
		e := symtab[i*elf.Sym64Size:]
		le.PutUint32(e[0:], 1)
		e[4] = byte(elf.STT_FUNC)
		le.PutUint64(e[8:], 0x401000+uint64(i)*16)
		le.PutUint64(e[16:], 16)
	}
	shstr := []byte("\x00.hidden\x00.strtab\x00.symtab\x00.shstrtab\x00")
	type section struct {
		name, typ, link uint32
		data            []byte
	}
	secs := []section{
		{name: 1, typ: uint32(elf.SHT_SYMTAB), link: 2, data: symtab},
		{name: 9, typ: uint32(elf.SHT_STRTAB), data: strtab},
		{name: 17, typ: uint32(elf.SHT_PROGBITS), data: make([]byte, elf.Sym64Size)},
		{name: 25, typ: uint32(elf.SHT_STRTAB), data: shstr},
	}
	buf := make([]byte, 64)
	offs := make([]int, len(secs))
	for i, s := range secs {
		for len(buf)%8 != 0 {
			buf = append(buf, 0)
		}
		offs[i] = len(buf)
		buf = append(buf, s.data...)
	}
	for len(buf)%8 != 0 {
		buf = append(buf, 0)
	}
	shoff := len(buf)
	buf = append(buf, make([]byte, 64*(len(secs)+1))...)
	copy(buf, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	le.PutUint16(buf[16:], uint16(elf.ET_EXEC))
	le.PutUint16(buf[18:], uint16(elf.EM_X86_64))
	le.PutUint32(buf[20:], 1)
	le.PutUint64(buf[40:], fileOffset(shoff))
	le.PutUint16(buf[52:], 64)
	le.PutUint16(buf[58:], 64)
	le.PutUint16(buf[60:], sectionCount(len(secs)+1))
	le.PutUint16(buf[62:], sectionCount(len(secs)))
	for i, s := range secs {
		h := buf[shoff+(i+1)*64:]
		le.PutUint32(h[0:], s.name)
		le.PutUint32(h[4:], s.typ)
		le.PutUint64(h[24:], fileOffset(offs[i]))
		le.PutUint64(h[32:], uint64(len(s.data)))
		le.PutUint32(h[40:], s.link)
		le.PutUint64(h[56:], elf.Sym64Size)
	}
	return buf
}

func allocatedDuring(fn func()) uint64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestSymbolsSharingOneLongNameHoldOneCopyOfIt(t *testing.T) {
	f, err := elf.NewFile(bytes.NewReader(sharedNameELF(40000, 16<<10)))
	if err != nil {
		t.Fatal(err)
	}
	var syms []funcSymbol
	var held int64
	alloc := allocatedDuring(func() { syms, held = functionSymbols(f, maxCachedSymbolBytes) })
	if len(syms) != 40000 {
		t.Fatalf("kept %d symbols, want 40000", len(syms))
	}
	for _, s := range syms[1:] {
		if unsafe.StringData(s.Name) != unsafe.StringData(syms[0].Name) {
			t.Fatal("symbols sharing a name hold separate copies of it")
		}
	}
	if want := 40000*funcSymbolBytes + 16<<10; held != want {
		t.Errorf("accounted %d bytes, want %d", held, want)
	}
	if mib := alloc >> 20; mib > 8 {
		t.Errorf("functionSymbols allocated %d MiB for 40000 symbols sharing one 16 KiB name", mib)
	}
}

func TestASymbolTableDeclaringMillionsOfFunctionsIsRefusedCheaply(t *testing.T) {
	f, err := elf.NewFile(bytes.NewReader(sharedNameELF(2_700_000, 1)))
	if err != nil {
		t.Fatal(err)
	}
	var syms []funcSymbol
	alloc := allocatedDuring(func() { syms, _ = functionSymbols(f, maxCachedSymbolBytes) })
	if syms != nil {
		t.Errorf("kept %d symbols past the %d byte budget", len(syms), maxCachedSymbolBytes)
	}
	if mib := alloc >> 20; mib > 160 {
		t.Errorf("allocated %d MiB refusing a 62 MiB symbol table", mib)
	}
}

func TestATableOverItsBudgetIsRefusedWhole(t *testing.T) {
	f, err := elf.NewFile(bytes.NewReader(sharedNameELF(100, 4)))
	if err != nil {
		t.Fatal(err)
	}
	if syms, held := functionSymbols(f, 99*funcSymbolBytes); syms != nil || held != 0 {
		t.Errorf("got %d symbols holding %d bytes, want none", len(syms), held)
	}
	if syms, _ := functionSymbols(f, 100*funcSymbolBytes+4); len(syms) != 100 {
		t.Errorf("got %d symbols within an exact budget, want 100", len(syms))
	}
	if got := symbolCapacity(f, 0); got != 0 {
		t.Errorf("capacity with no budget = %d", got)
	}
}

func TestThe32BitSymbolEntrySizesTheCapacity(t *testing.T) {
	f := &elf.File{
		FileHeader: elf.FileHeader{Class: elf.ELFCLASS32},
		Sections:   []*elf.Section{{SectionHeader: elf.SectionHeader{Type: elf.SHT_SYMTAB, Size: 10 * elf.Sym32Size}}},
	}
	if got := symbolCapacity(f, maxCachedSymbolBytes); got != 10 {
		t.Errorf("capacity of ten 32-bit entries = %d", got)
	}
	if got := symbolCapacity(f, 3*funcSymbolBytes); got != 3 {
		t.Errorf("capacity within a three-symbol budget = %d", got)
	}
}
