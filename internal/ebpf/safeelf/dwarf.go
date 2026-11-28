package safeelf

import (
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
)

// Bounds on what debug/dwarf allocates up front in dwarf.New. It keeps a
// record per unit header, and it parses the abbreviation table at every
// distinct offset a unit names, from that offset to the table's end.
const (
	MaxDWARFUnits = 1 << 17

	MaxDWARFAbbrevCost = uint64(64) << 20

	abbrevEntryCost = 64
	abbrevFieldCost = 24
)

// dwarfReaderSections are the sections a dwarf.Reader decodes entries from.
// Line tables, ranges, location lists and type units are only reached through
// other dwarf.Data methods, which nothing here calls.
var dwarfReaderSections = []string{"abbrev", "info", "str", "line_str", "str_offsets", "addr"}

var errRelocatableDWARF = errors.New("dwarf in a relocatable object needs relocations, which are not applied")

// DWARF returns the debug information of f for walking with a dwarf.Reader,
// within the caps above.
//
// Unlike elf.File.DWARF it applies no relocation sections. A linked
// executable or shared object already has its debug sections relocated, and
// applying a hostile file's relocations reads relocation and symbol tables
// that no cap bounds. A relocatable object, which does need them, is refused.
func DWARF(f *elf.File) (*dwarf.Data, error) {
	if f.Type == elf.ET_REL {
		return nil, errRelocatableDWARF
	}
	sections, err := dwarfReaderSectionSizes(f)
	if err != nil {
		return nil, err
	}
	data := make(map[string][]byte, len(sections))
	for _, s := range sections {
		b, err := readSection(s.section, s.size)
		if err != nil {
			return nil, err
		}
		data[s.suffix] = b
	}
	if err := dwarfParseCostWithinCap(data["info"], data["abbrev"]); err != nil {
		return nil, err
	}
	d, err := dwarf.New(data["abbrev"], nil, nil, data["info"], nil, nil, nil, data["str"])
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"line_str", "str_offsets", "addr"} {
		if b := data[name]; b != nil {
			_ = d.AddSection(".debug_"+name, b)
		}
	}
	return d, nil
}

type sizedSection struct {
	suffix  string
	section *elf.Section
	size    uint64
}

// dwarfReaderSectionSizes picks the first section of each name the Reader
// uses and the size reading it costs, refusing a total over
// MaxDWARFTotalSize.
func dwarfReaderSectionSizes(f *elf.File) ([]sizedSection, error) {
	var picked []sizedSection
	var total uint64
	for _, s := range f.Sections {
		suffix := dwarfSuffix(s.Name)
		if !isReaderSection(suffix) || hasSuffix(picked, suffix) {
			continue
		}
		size := s.Size
		if strings.HasPrefix(s.Name, ".zdebug") && s.Flags&elf.SHF_COMPRESSED == 0 {
			size = zdebugDeclaredSize(s)
		}
		if size > MaxDWARFTotalSize-total {
			return nil, fmt.Errorf("dwarf sections exceed %d bytes", MaxDWARFTotalSize)
		}
		total += size
		picked = append(picked, sizedSection{suffix: suffix, section: s, size: size})
	}
	return picked, nil
}

func hasSuffix(picked []sizedSection, suffix string) bool {
	for _, p := range picked {
		if p.suffix == suffix {
			return true
		}
	}
	return false
}

func dwarfSuffix(name string) string {
	switch {
	case strings.HasPrefix(name, ".debug_"):
		return name[len(".debug_"):]
	case strings.HasPrefix(name, ".zdebug_"):
		return name[len(".zdebug_"):]
	}
	return ""
}

func isReaderSection(suffix string) bool {
	for _, s := range dwarfReaderSections {
		if s == suffix {
			return true
		}
	}
	return false
}

// zdebugDeclaredSize returns the uncompressed size a .zdebug_* section's
// "ZLIB" header declares. A section without that header is read raw by
// debug/elf, so its stored size is what it costs.
func zdebugDeclaredSize(s *elf.Section) uint64 {
	if s.Type == elf.SHT_NOBITS || s.ReaderAt == nil {
		return s.Size
	}
	var header [12]byte
	if n, _ := s.ReadAt(header[:], 0); n != len(header) || string(header[:4]) != "ZLIB" {
		return s.Size
	}
	return binary.BigEndian.Uint64(header[4:])
}

// dwarfParseCostWithinCap walks the unit headers of info and the abbreviation
// tables they name the way dwarf.New will, and refuses data that would make
// it allocate past MaxDWARFUnits or MaxDWARFAbbrevCost.
func dwarfParseCostWithinCap(info, abbrev []byte) error {
	offsets, err := dwarfAbbrevOffsets(info)
	if err != nil {
		return err
	}
	slices.Sort(offsets)
	var cost uint64
	for _, off := range slices.Compact(offsets) {
		cost += abbrevTableCost(abbrev, off)
		if cost > MaxDWARFAbbrevCost {
			return fmt.Errorf("dwarf abbreviation tables too costly to parse: over %d bytes", MaxDWARFAbbrevCost)
		}
	}
	return nil
}

// dwarfAbbrevOffsets returns the abbreviation offset of every non-empty unit
// in info, refusing more than MaxDWARFUnits before it allocates for them.
func dwarfAbbrevOffsets(info []byte) ([]uint64, error) {
	order, ok := dwarfByteOrder(info)
	if !ok {
		return nil, nil
	}
	n := 0
	walkUnits(info, order, func([]byte, bool) bool {
		n++
		return n <= MaxDWARFUnits
	})
	if n > MaxDWARFUnits {
		return nil, fmt.Errorf("dwarf has more than %d units", MaxDWARFUnits)
	}
	offsets := make([]uint64, 0, n)
	walkUnits(info, order, func(body []byte, is64 bool) bool {
		if off, ok := unitAbbrevOffset(body, order, is64); ok {
			offsets = append(offsets, off)
		}
		return true
	})
	return offsets, nil
}

// walkUnits calls fn with the body of each non-empty unit in info until fn
// returns false or the unit headers stop making sense.
func walkUnits(info []byte, order binary.ByteOrder, fn func(body []byte, is64 bool) bool) {
	for off := uint64(0); off < uint64(len(info)); {
		length, is64, hdr, ok := unitLength(info[off:], order)
		if !ok {
			return
		}
		body := off + hdr
		if length > uint64(len(info))-body {
			return
		}
		off = body + length
		if length > 0 && !fn(info[body:off], is64) {
			return
		}
	}
}

// dwarfByteOrder reads the byte order from the version of the first unit, as
// dwarf.New does.
func dwarfByteOrder(info []byte) (binary.ByteOrder, bool) {
	at := 4
	if len(info) >= 4 && binary.LittleEndian.Uint32(info) == 0xffffffff {
		at = 12
	}
	if len(info) < at+2 {
		return nil, false
	}
	switch x, y := info[at], info[at+1]; {
	case x == 0 && y != 0:
		return binary.BigEndian, true
	case y == 0 && x != 0:
		return binary.LittleEndian, true
	}
	return nil, false
}

// unitLength decodes a unit's initial length field and returns the length,
// whether the unit is 64-bit DWARF and the size of the length field.
func unitLength(b []byte, order binary.ByteOrder) (length uint64, is64 bool, hdr uint64, ok bool) {
	if len(b) < 4 {
		return 0, false, 0, false
	}
	l32 := order.Uint32(b)
	switch {
	case l32 == 0xffffffff:
		if len(b) < 12 {
			return 0, false, 0, false
		}
		return order.Uint64(b[4:]), true, 12, true
	case l32 >= 0xfffffff0:
		return 0, false, 0, false
	}
	return uint64(l32), false, 4, true
}

// unitAbbrevOffset reads the abbreviation offset from a unit's body, which
// follows the version, and in DWARF 5 the unit type and address size.
func unitAbbrevOffset(body []byte, order binary.ByteOrder, is64 bool) (uint64, bool) {
	if len(body) < 2 {
		return 0, false
	}
	at := 2
	if order.Uint16(body) >= 5 {
		at += 2
	}
	width := 4
	if is64 {
		width = 8
	}
	if len(body) < at+width {
		return 0, false
	}
	if is64 {
		return order.Uint64(body[at:]), true
	}
	return uint64(order.Uint32(body[at:])), true
}

// formImplicitConst is DW_FORM_implicit_const, whose value is stored in the
// abbreviation itself.
const formImplicitConst = 0x21

// abbrevTableCost returns what dwarf.New allocates to parse the abbreviation
// table at off: an entry per abbreviation and a field per attribute.
func abbrevTableCost(abbrev []byte, off uint64) uint64 {
	if off >= uint64(len(abbrev)) {
		return 0
	}
	b := abbrev[off:]
	var cost uint64
	for {
		id, ok := uleb(&b)
		if !ok || id&math.MaxUint32 == 0 {
			return cost
		}
		if _, ok := uleb(&b); !ok || len(b) == 0 {
			return cost
		}
		b = b[1:]
		cost += abbrevEntryCost
		for {
			attr, ok1 := uleb(&b)
			form, ok2 := uleb(&b)
			if !ok1 || !ok2 || (attr == 0 && form == 0) {
				break
			}
			if form&math.MaxUint32 == formImplicitConst {
				if _, ok := uleb(&b); !ok {
					break
				}
			}
			cost += abbrevFieldCost
			if cost > MaxDWARFAbbrevCost {
				return cost
			}
		}
	}
}

// uleb consumes one LEB128 number from b the way debug/dwarf does: of any
// length, keeping the low 64 bits, and failing only when b ends first. Signed
// numbers have the same length, so it also skips those.
func uleb(b *[]byte) (uint64, bool) {
	var v uint64
	var shift uint
	for i, c := range *b {
		if shift < 64 {
			v |= uint64(c&0x7f) << shift
		}
		shift += 7
		if c&0x80 == 0 {
			*b = (*b)[i+1:]
			return v, true
		}
	}
	return 0, false
}
