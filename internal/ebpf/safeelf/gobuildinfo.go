package safeelf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"

	"github.com/gma1k/podtrace/internal/safeconv"
)

// Bounds on reading a Go executable's toolchain version. debug/buildinfo
// reads a length-prefixed string up to the size of whichever program header
// holds it, of any type, so a hostile header and length make it allocate
// gigabytes from a sparse file. A real version string is under 100 bytes and
// the header sits at the start of .go.buildinfo.
const (
	maxGoBuildInfoPrefix = 64 << 10

	MaxGoVersionLength = 256

	goBuildInfoHeaderSize = 32
	goBuildInfoAlign      = 16
)

var goBuildInfoMagic = []byte("\xff Go buildinf:")

// GoVersion returns the Go toolchain version recorded in f's .go.buildinfo
// section, such as "go1.26.2".
func GoVersion(f *elf.File) (string, bool) {
	sec := f.Section(".go.buildinfo")
	if sec == nil {
		return "", false
	}
	data, err := SectionPrefix(sec, maxGoBuildInfoPrefix)
	if err != nil {
		return "", false
	}
	start, ok := goBuildInfoHeader(data, sec.Addr)
	if !ok {
		return "", false
	}
	header := data[start : start+goBuildInfoHeaderSize]
	const (
		ptrSizeOffset  = 14
		flagsOffset    = 15
		versionPointer = 16
		bigEndianFlag  = 0x1
		inlineFlag     = 0x2
	)
	flags := header[flagsOffset]
	if flags&inlineFlag != 0 {
		return inlineGoVersion(data[start+goBuildInfoHeaderSize:])
	}
	var order binary.ByteOrder = binary.LittleEndian
	if flags&bigEndianFlag != 0 {
		order = binary.BigEndian
	}
	ptrSize := int(header[ptrSizeOffset])
	if ptrSize != 4 && ptrSize != 8 {
		return "", false
	}
	return pointedGoVersion(f, order, ptrSize, readPointer(header[versionPointer:], order, ptrSize))
}

// goBuildInfoHeader returns where the build info header starts in data: the
// first occurrence of the magic at an aligned address with a whole header
// after it.
func goBuildInfoHeader(data []byte, addr uint64) (int, bool) {
	for at := 0; at+goBuildInfoHeaderSize <= len(data); {
		i := bytes.Index(data[at:], goBuildInfoMagic)
		if i < 0 {
			return 0, false
		}
		at += i
		if (addr+uint64(at))%goBuildInfoAlign == 0 {
			return at, at+goBuildInfoHeaderSize <= len(data)
		}
		at++
	}
	return 0, false
}

// inlineGoVersion decodes the varint-prefixed version string that Go 1.18
// and later store right after the header.
func inlineGoVersion(b []byte) (string, bool) {
	length, n := binary.Uvarint(b)
	if n <= 0 || length == 0 || length > MaxGoVersionLength || length > safeconv.IntToUint64(len(b)-n) {
		return "", false
	}
	return string(b[n : n+int(length)]), true
}

func readPointer(b []byte, order binary.ByteOrder, ptrSize int) uint64 {
	if ptrSize == 4 {
		return uint64(order.Uint32(b))
	}
	return order.Uint64(b)
}

// pointedGoVersion follows the pointer to a Go string header that Go 1.17
// and earlier store in the header, reading both the header and the string
// from loadable segments.
func pointedGoVersion(f *elf.File, order binary.ByteOrder, ptrSize int, addr uint64) (string, bool) {
	hdr, ok := loadedBytes(f, addr, safeconv.IntToUint64(2*ptrSize))
	if !ok {
		return "", false
	}
	dataAddr := readPointer(hdr, order, ptrSize)
	length := readPointer(hdr[ptrSize:], order, ptrSize)
	if length == 0 || length > MaxGoVersionLength {
		return "", false
	}
	b, ok := loadedBytes(f, dataAddr, length)
	if !ok {
		return "", false
	}
	return string(b), true
}

// loadedBytes reads n bytes at virtual address addr from the PT_LOAD segment
// that holds all of them in the file.
func loadedBytes(f *elf.File, addr, n uint64) ([]byte, bool) {
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || addr < p.Vaddr || addr-p.Vaddr > p.Filesz || n > p.Filesz-(addr-p.Vaddr) {
			continue
		}
		b := make([]byte, n)
		if _, err := p.ReadAt(b, safeconv.Uint64ToInt64(addr-p.Vaddr)); err != nil {
			return nil, false
		}
		return b, true
	}
	return nil, false
}
