package stacktrace

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"math"
	"runtime"
	"testing"
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
		le.PutUint64(e[8:], 0x401000)
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

func TestSymbolizingABinaryWhoseSymbolsShareOneLongNameIsRefused(t *testing.T) {
	f, err := elf.NewFile(bytes.NewReader(sharedNameELF(40000, 16<<10)))
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	syms := functionSymbols(f)
	runtime.ReadMemStats(&after)
	if syms != nil {
		t.Errorf("functionSymbols returned %d symbols", len(syms))
	}
	if mib := (after.TotalAlloc - before.TotalAlloc) >> 20; mib > 8 {
		t.Errorf("functionSymbols allocated %d MiB; debug/elf copies a name per symbol", mib)
	}
}
