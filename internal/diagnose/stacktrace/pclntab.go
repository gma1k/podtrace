package stacktrace

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"io"
	"sort"

	"github.com/gma1k/podtrace/internal/safeconv"
)

// Magic numbers of the pclntab layouts debug/gosym reads. Go 1.20 changed
// nothing a function-name lookup depends on, so it reads as Go 1.18.
const (
	go12PCLnTabMagic  = 0xfffffffb
	go116PCLnTabMagic = 0xfffffffa
	go118PCLnTabMagic = 0xfffffff0
	go120PCLnTabMagic = 0xfffffff1
)

const maxFunctionNameLen = 4096

// Bounds on what a pclntab may claim.
const (
	maxPCLNFunctions   = 1 << 22
	maxPCLNSectionSize = 1 << 31
	maxPCLNFileOffset  = 1 << 40
)

// pclnIndex resolves a Go function name straight from the executable, holding
// only the function table in memory, whatever the size of the rest.
type pclnIndex struct {
	order binary.ByteOrder

	sectionOffset uint64
	sectionSize   uint64

	// pcBase is added to every function-table entry: .text's address from
	// Go 1.18 on, whose entries are offsets into it, and 0 before, whose
	// entries are absolute addresses.
	pcBase uint64

	funcnametab uint64
	funcdata    uint64

	// fieldSize is the width of a function-table field, and of the entry
	// field that starts each function's record: 4 bytes from Go 1.18 on, a
	// pointer before.
	fieldSize uint64

	nfunc   int
	functab []byte
}

// pclnLayout is where one pclntab version keeps what a name lookup reads, as
// header words or fixed offsets.
type pclnLayout struct {
	words       uint64
	nameTabWord uint64
	funcWord    uint64
	hasOffsets  bool
	pcRelative  bool
	ptrFields   bool
}

// pclnLayoutFor returns the layout of the pclntab with magic m, read the way
// debug/gosym reads each version.
func pclnLayoutFor(m uint32) (pclnLayout, bool) {
	switch m {
	case go118PCLnTabMagic, go120PCLnTabMagic:
		return pclnLayout{words: 8, nameTabWord: 3, funcWord: 7, hasOffsets: true, pcRelative: true}, true
	case go116PCLnTabMagic:
		return pclnLayout{words: 7, nameTabWord: 2, funcWord: 6, hasOffsets: true, ptrFields: true}, true
	case go12PCLnTabMagic:
		return pclnLayout{words: 1, ptrFields: true}, true
	}
	return pclnLayout{}, false
}

// loadPCLNIndex reads the header and function table of a Go 1.2+ pclntab.
func loadPCLNIndex(f *elf.File) (*pclnIndex, bool) {
	sect := f.Section(".gopclntab")
	text := f.Section(".text")
	if sect == nil || text == nil || sect.Type == elf.SHT_NOBITS || sect.Flags&elf.SHF_COMPRESSED != 0 {
		return nil, false
	}
	return parsePCLNIndex(sect, sect.Offset, sect.Size, text.Addr)
}

// parsePCLNIndex reads the index from sect, the pclntab's bytes, which sit at
// sectionOffset in the file and are size bytes long.
func parsePCLNIndex(sect io.ReaderAt, sectionOffset, size, textStart uint64) (*pclnIndex, bool) {
	if size > maxPCLNSectionSize || sectionOffset > maxPCLNFileOffset {
		return nil, false
	}
	var head [8]byte
	if _, err := sect.ReadAt(head[:], 0); err != nil {
		return nil, false
	}
	if head[4] != 0 || head[5] != 0 {
		return nil, false
	}
	if q := head[6]; q != 1 && q != 2 && q != 4 {
		return nil, false
	}
	ptrSize := uint64(head[7])
	if ptrSize != 4 && ptrSize != 8 {
		return nil, false
	}

	var order binary.ByteOrder = binary.LittleEndian
	layout, ok := pclnLayoutFor(order.Uint32(head[:]))
	if !ok {
		order = binary.BigEndian
		if layout, ok = pclnLayoutFor(order.Uint32(head[:])); !ok {
			return nil, false
		}
	}

	words := make([]byte, layout.words*ptrSize)
	if _, err := sect.ReadAt(words, 8); err != nil {
		return nil, false
	}
	word := func(i uint64) uint64 {
		b := words[i*ptrSize:]
		if ptrSize == 8 {
			return order.Uint64(b)
		}
		return uint64(order.Uint32(b))
	}

	idx := &pclnIndex{
		order:         order,
		sectionOffset: sectionOffset,
		sectionSize:   size,
		fieldSize:     4,
	}
	nfunc := word(0)
	functabAt := 8 + ptrSize
	if layout.hasOffsets {
		idx.funcnametab = word(layout.nameTabWord)
		idx.funcdata = word(layout.funcWord)
		functabAt = idx.funcdata
	}
	if layout.pcRelative {
		idx.pcBase = textStart
	}
	if layout.ptrFields {
		idx.fieldSize = ptrSize
	}
	if nfunc == 0 || nfunc > size/8 || nfunc > maxPCLNFunctions || idx.funcnametab >= size || idx.funcdata >= size {
		return nil, false
	}
	functabLen := (2*nfunc + 1) * idx.fieldSize
	if functabAt > size || size-functabAt < functabLen {
		return nil, false
	}

	idx.functab = make([]byte, functabLen)
	if _, err := sect.ReadAt(idx.functab, safeconv.Uint64ToInt64(functabAt)); err != nil {
		return nil, false
	}
	idx.nfunc = int(safeconv.Uint64ToUint32(nfunc))
	return idx, true
}

func (p *pclnIndex) field(i uint64) uint64 {
	b := p.functab[i*p.fieldSize:]
	if p.fieldSize == 8 {
		return p.order.Uint64(b)
	}
	return uint64(p.order.Uint32(b))
}

func (p *pclnIndex) entry(i int) uint64 {
	return p.field(2 * safeconv.IntToUint64(i))
}

func (p *pclnIndex) funcOff(i int) uint64 {
	return p.field(2*safeconv.IntToUint64(i) + 1)
}

// covers reports whether pc falls inside the Go functions this table
// describes.
func (p *pclnIndex) covers(pc uint64) bool {
	if pc < p.pcBase {
		return false
	}
	rel := pc - p.pcBase
	return rel >= p.entry(0) && rel < p.entry(p.nfunc)
}

// name returns the Go function containing pc, reading its name from r, which
// must be the executable the index was built from.
func (p *pclnIndex) name(r io.ReaderAt, pc uint64) string {
	if !p.covers(pc) {
		return ""
	}
	rel := pc - p.pcBase
	i := sort.Search(p.nfunc, func(i int) bool { return p.entry(i) > rel }) - 1

	off := p.funcOff(i)
	if off >= p.sectionSize || p.funcdata+off+p.fieldSize+4 > p.sectionSize {
		return ""
	}
	nameOffAt := p.funcdata + off + p.fieldSize
	var raw [4]byte
	if _, err := r.ReadAt(raw[:], safeconv.Uint64ToInt64(p.sectionOffset+nameOffAt)); err != nil {
		return ""
	}
	nameAt := p.funcnametab + uint64(p.order.Uint32(raw[:]))
	if nameAt >= p.sectionSize {
		return ""
	}

	limit := p.sectionSize - nameAt
	if limit > maxFunctionNameLen {
		limit = maxFunctionNameLen
	}
	buf := make([]byte, limit)
	n, err := r.ReadAt(buf, safeconv.Uint64ToInt64(p.sectionOffset+nameAt))
	if err != nil && err != io.EOF {
		return ""
	}
	buf = buf[:n]
	end := bytes.IndexByte(buf, 0)
	if end <= 0 {
		return ""
	}
	return string(buf[:end])
}
