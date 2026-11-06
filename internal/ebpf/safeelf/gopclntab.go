package safeelf

import (
	"encoding/binary"
	"math"
)

// Magic numbers of the .gopclntab layouts debug/gosym understands.
const (
	Go12PCLNTabMagic  = 0xfffffffb
	Go116PCLNTabMagic = 0xfffffffa
	Go118PCLNTabMagic = 0xfffffff0
	Go120PCLNTabMagic = 0xfffffff1
)

// Bounds on what a .gopclntab header may claim before debug/gosym parses it.
// gosym.NewTable allocates per claimed function, and it caches every
// file-table string by offset, so a header claiming millions of empty file
// names over a zero-filled region costs about 65 bytes per byte of section.
// Real binaries stay far below both caps: a 158k-function cilium binary has
// about 7k file-table entries.
const (
	MaxGoFunctionCount  = uint64(1) << 20
	MaxGoFileTableCount = uint64(1) << 18
)

// GoPCLNTabWithinCap reports whether a .gopclntab's claimed function and
// file-table counts are small enough for debug/gosym to parse.
func GoPCLNTabWithinCap(data []byte) bool {
	if len(data) < 8 {
		return true
	}
	ptrSize := uint64(data[7])
	if ptrSize != 4 && ptrSize != 8 {
		return true
	}
	var order binary.ByteOrder
	var magic uint32
	switch {
	case knownPCLNMagic(binary.LittleEndian.Uint32(data)):
		order, magic = binary.LittleEndian, binary.LittleEndian.Uint32(data)
	case knownPCLNMagic(binary.BigEndian.Uint32(data)):
		order, magic = binary.BigEndian, binary.BigEndian.Uint32(data)
	default:
		return true
	}
	word := func(at uint64) (uint64, bool) {
		if at > uint64(len(data)) || uint64(len(data))-at < ptrSize {
			return 0, false
		}
		if ptrSize == 8 {
			return order.Uint64(data[at:]), true
		}
		return uint64(order.Uint32(data[at:])), true
	}

	nfunc, ok := word(8)
	if !ok {
		return true
	}
	if nfunc > MaxGoFunctionCount {
		return false
	}
	nfiletab, ok := fileTableCount(data, order, magic, ptrSize, nfunc, word)
	return !ok || nfiletab <= MaxGoFileTableCount
}

// fileTableCount returns the number of file-table entries the header claims,
// read from where debug/gosym reads it for each layout.
func fileTableCount(data []byte, order binary.ByteOrder, magic uint32, ptrSize, nfunc uint64,
	word func(uint64) (uint64, bool)) (uint64, bool) {
	if magic != Go12PCLNTabMagic {
		n, ok := word(8 + ptrSize)
		return n & math.MaxUint32, ok
	}
	fileOffAt := 8 + ptrSize + (2*nfunc+1)*ptrSize
	if fileOffAt > uint64(len(data)) || uint64(len(data))-fileOffAt < 4 {
		return 0, false
	}
	fileOff := uint64(order.Uint32(data[fileOffAt:]))
	if fileOff > uint64(len(data)) || uint64(len(data))-fileOff < 4 {
		return 0, false
	}
	return uint64(order.Uint32(data[fileOff:])), true
}

func knownPCLNMagic(m uint32) bool {
	switch m {
	case Go12PCLNTabMagic, Go116PCLNTabMagic, Go118PCLNTabMagic, Go120PCLNTabMagic:
		return true
	}
	return false
}
