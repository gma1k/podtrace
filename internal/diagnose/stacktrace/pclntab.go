package stacktrace

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"io"
	"sort"

	"github.com/gma1k/podtrace/internal/safeconv"
)

// Magic numbers of the Go 1.18 and Go 1.20 pclntab layouts, which are the
// same on disk as far as a function-name lookup is concerned.
const (
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
// only the function table in memory.
type pclnIndex struct {
	order binary.ByteOrder

	sectionOffset uint64
	sectionSize   uint64

	textStart uint64

	funcnametab uint64
	funcdata    uint64

	nfunc   int
	functab []byte
}

// loadPCLNIndex reads the header and function table of a Go 1.18+ pclntab.
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

	var order binary.ByteOrder
	switch {
	case isGo118Magic(binary.LittleEndian.Uint32(head[:])):
		order = binary.LittleEndian
	case isGo118Magic(binary.BigEndian.Uint32(head[:])):
		order = binary.BigEndian
	default:
		return nil, false
	}

	words := make([]byte, 8*ptrSize)
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

	nfunc := word(0)
	funcnametab := word(3)
	funcdata := word(7)
	if nfunc == 0 || nfunc > size/8 || nfunc > maxPCLNFunctions || funcnametab >= size || funcdata >= size {
		return nil, false
	}
	functabLen := (2*nfunc + 1) * 4
	if funcdata+functabLen > size {
		return nil, false
	}

	functab := make([]byte, functabLen)
	if _, err := sect.ReadAt(functab, safeconv.Uint64ToInt64(funcdata)); err != nil {
		return nil, false
	}

	return &pclnIndex{
		order:         order,
		sectionOffset: sectionOffset,
		sectionSize:   size,
		textStart:     textStart,
		funcnametab:   funcnametab,
		funcdata:      funcdata,
		nfunc:         int(safeconv.Uint64ToUint32(nfunc)),
		functab:       functab,
	}, true
}

func isGo118Magic(m uint32) bool {
	return m == go118PCLnTabMagic || m == go120PCLnTabMagic
}

func (p *pclnIndex) entry(i int) uint64 {
	return uint64(p.order.Uint32(p.functab[8*i:]))
}

func (p *pclnIndex) funcOff(i int) uint64 {
	return uint64(p.order.Uint32(p.functab[8*i+4:]))
}

// covers reports whether pc falls inside the Go functions this table
// describes.
func (p *pclnIndex) covers(pc uint64) bool {
	if pc < p.textStart {
		return false
	}
	rel := pc - p.textStart
	return rel >= p.entry(0) && rel < p.entry(p.nfunc)
}

// name returns the Go function containing pc, reading its name from r, which
// must be the executable the index was built from.
func (p *pclnIndex) name(r io.ReaderAt, pc uint64) string {
	if !p.covers(pc) {
		return ""
	}
	rel := pc - p.textStart
	i := sort.Search(p.nfunc, func(i int) bool { return p.entry(i) > rel }) - 1

	nameOffAt := p.funcdata + p.funcOff(i) + 4
	if nameOffAt+4 > p.sectionSize {
		return ""
	}
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
