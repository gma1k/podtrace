package safeelf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func u16(n int) uint16 {
	if n < 0 || n > math.MaxUint16 {
		panic("value does not fit in 16 bits")
	}
	return uint16(n)
}

func u32(n uint64) uint32 {
	if n > math.MaxUint32 {
		panic("value does not fit in 32 bits")
	}
	return uint32(n)
}

func length(n int) uint64 {
	if n < 0 {
		panic("negative length")
	}
	return uint64(n)
}

func offset(n uint64) int {
	if n > math.MaxInt32 {
		panic("offset too large")
	}
	return int(n)
}

type rawSection struct {
	name     string
	typ      elf.SectionType
	flags    elf.SectionFlag
	link     uint32
	entsize  uint64
	data     []byte
	declared uint64
}

func buildELF(class elf.Class, secs []rawSection) []byte {
	le := binary.LittleEndian
	is64 := class == elf.ELFCLASS64
	ehsize, shentsize := 52, 40
	if is64 {
		ehsize, shentsize = 64, 64
	}
	shstr := []byte{0}
	names := make([]uint32, len(secs)+1)
	for i, s := range secs {
		names[i] = u32(length(len(shstr)))
		shstr = append(shstr, s.name+"\x00"...)
	}
	names[len(secs)] = u32(length(len(shstr)))
	shstr = append(shstr, ".shstrtab\x00"...)
	all := append(append([]rawSection{}, secs...), rawSection{typ: elf.SHT_STRTAB, data: shstr})

	buf := make([]byte, ehsize)
	offs := make([]uint64, len(all))
	for i, s := range all {
		for len(buf)%8 != 0 {
			buf = append(buf, 0)
		}
		offs[i] = length(len(buf))
		buf = append(buf, s.data...)
	}
	for len(buf)%8 != 0 {
		buf = append(buf, 0)
	}
	shoff := length(len(buf))
	shnum := len(all) + 1
	buf = append(buf, make([]byte, shnum*shentsize)...)

	copy(buf, []byte{0x7f, 'E', 'L', 'F', byte(class), 1, 1})
	le.PutUint16(buf[16:], uint16(elf.ET_EXEC))
	le.PutUint32(buf[20:], 1)
	if is64 {
		le.PutUint16(buf[18:], uint16(elf.EM_X86_64))
		le.PutUint64(buf[40:], shoff)
		le.PutUint16(buf[52:], u16(ehsize))
		le.PutUint16(buf[58:], u16(shentsize))
		le.PutUint16(buf[60:], u16(shnum))
		le.PutUint16(buf[62:], u16(shnum-1))
	} else {
		le.PutUint16(buf[18:], uint16(elf.EM_386))
		le.PutUint32(buf[32:], u32(shoff))
		le.PutUint16(buf[40:], u16(ehsize))
		le.PutUint16(buf[46:], u16(shentsize))
		le.PutUint16(buf[48:], u16(shnum))
		le.PutUint16(buf[50:], u16(shnum-1))
	}
	for i, s := range all {
		size := length(len(s.data))
		if s.declared != 0 {
			size = s.declared
		}
		h := buf[offset(shoff)+(i+1)*shentsize:]
		le.PutUint32(h[0:], names[i])
		le.PutUint32(h[4:], uint32(s.typ))
		if is64 {
			le.PutUint64(h[8:], uint64(s.flags))
			le.PutUint64(h[24:], offs[i])
			le.PutUint64(h[32:], size)
			le.PutUint32(h[40:], s.link)
			le.PutUint64(h[48:], 1)
			le.PutUint64(h[56:], s.entsize)
		} else {
			le.PutUint32(h[8:], uint32(s.flags))
			le.PutUint32(h[16:], u32(offs[i]))
			le.PutUint32(h[20:], u32(size))
			le.PutUint32(h[24:], s.link)
			le.PutUint32(h[32:], 1)
			le.PutUint32(h[36:], u32(s.entsize))
		}
	}
	return buf
}

func parseELF(t *testing.T, class elf.Class, secs []rawSection) *elf.File {
	t.Helper()
	f, err := elf.NewFile(bytes.NewReader(buildELF(class, secs)))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

type testSymbol struct {
	name  string
	info  byte
	value uint64
}

func symbolSections(class elf.Class, tableType elf.SectionType, syms ...testSymbol) []rawSection {
	le := binary.LittleEndian
	entsize := elf.Sym32Size
	if class == elf.ELFCLASS64 {
		entsize = elf.Sym64Size
	}
	strtab := []byte{0}
	table := make([]byte, entsize)
	for _, s := range syms {
		e := make([]byte, entsize)
		le.PutUint32(e[0:], u32(length(len(strtab))))
		if class == elf.ELFCLASS64 {
			e[4] = s.info
			le.PutUint16(e[6:], 1)
			le.PutUint64(e[8:], s.value)
			le.PutUint64(e[16:], 16)
		} else {
			le.PutUint32(e[4:], u32(s.value))
			le.PutUint32(e[8:], 16)
			e[12] = s.info
			le.PutUint16(e[14:], 1)
		}
		table = append(table, e...)
		strtab = append(strtab, s.name+"\x00"...)
	}
	return []rawSection{
		{name: ".table", typ: tableType, link: 2, entsize: length(entsize), data: table},
		{name: ".names", typ: elf.SHT_STRTAB, data: strtab},
	}
}

func writeSparseELF(t *testing.T, secs []rawSection, size int64) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sparse.elf")
	if err := os.WriteFile(path, buildELF(elf.ELFCLASS64, secs), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, size); err != nil {
		t.Fatal(err)
	}
	return path
}

func allocatedMiB(f func()) uint64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return (after.TotalAlloc - before.TotalAlloc) >> 20
}
