package safeelf

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"strings"
)

// Symbol is one entry of an ELF symbol table, without its name.
type Symbol struct {
	Info    byte
	Section elf.SectionIndex
	Value   uint64
	Size    uint64
}

// ErrSymbolTableTooLarge refuses a symbol table, or its string table, that
// is over the caps or stored compressed.
var ErrSymbolTableTooLarge = errors.New("symbol table too large to parse safely")

// symbolTableVersionSections are the GNU symbol-versioning sections
// debug/elf reads whole alongside .dynsym.
var symbolTableVersionSections = []elf.SectionType{elf.SHT_GNU_VERSYM, elf.SHT_GNU_VERNEED, elf.SHT_GNU_VERDEF}

// ForEachSymbol calls fn for every symbol in f's first table of type typ,
// SHT_SYMTAB or SHT_DYNSYM, the one debug/elf would parse, skipping the
// reserved null entry, until fn returns false. The name is a view into the
// string table, valid only during the call, so a table naming every symbol
// with the same long string costs nothing per symbol. A file without such a
// table returns elf.ErrNoSymbols.
func ForEachSymbol(f *elf.File, typ elf.SectionType, fn func(name []byte, sym Symbol) bool) error {
	syms, strs, err := symbolTableData(f, typ)
	if err != nil {
		return err
	}
	var size int
	switch f.Class {
	case elf.ELFCLASS64:
		size = elf.Sym64Size
	case elf.ELFCLASS32:
		size = elf.Sym32Size
	default:
		return fmt.Errorf("unknown ELF class %v", f.Class)
	}
	if len(syms)%size != 0 {
		return errors.New("symbol table size is not a multiple of its entry size")
	}
	order := f.ByteOrder
	for off := size; off+size <= len(syms); off += size {
		entry := syms[off : off+size]
		var sym Symbol
		var nameOff uint32
		if f.Class == elf.ELFCLASS64 {
			nameOff = order.Uint32(entry[0:4])
			sym.Info = entry[4]
			sym.Section = elf.SectionIndex(order.Uint16(entry[6:8]))
			sym.Value = order.Uint64(entry[8:16])
			sym.Size = order.Uint64(entry[16:24])
		} else {
			nameOff = order.Uint32(entry[0:4])
			sym.Value = uint64(order.Uint32(entry[4:8]))
			sym.Size = uint64(order.Uint32(entry[8:12]))
			sym.Info = entry[12]
			sym.Section = elf.SectionIndex(order.Uint16(entry[14:16]))
		}
		if !fn(symbolName(strs, nameOff), sym) {
			return nil
		}
	}
	return nil
}

// symbolName returns the NUL-terminated string at off in strs, or nil when
// off is outside strs or the string is unterminated, as debug/elf does.
func symbolName(strs []byte, off uint32) []byte {
	if uint64(off) >= uint64(len(strs)) {
		return nil
	}
	rest := strs[off:]
	end := bytes.IndexByte(rest, 0)
	if end < 0 {
		return nil
	}
	return rest[:end]
}

// symbolTableData returns the raw entries of f's first symbol table of type
// typ and the string table it links to, both within MaxSymbolTableSize.
func symbolTableData(f *elf.File, typ elf.SectionType) (syms, strs []byte, err error) {
	sec := f.SectionByType(typ)
	if sec == nil {
		return nil, nil, elf.ErrNoSymbols
	}
	if sec.Link == 0 || int(sec.Link) >= len(f.Sections) {
		return nil, nil, errors.New("symbol table has an invalid string table link")
	}
	strtab := f.Sections[sec.Link]
	if !storedPlainWithin(sec, MaxSymbolTableSize) || !storedPlainWithin(strtab, MaxSymbolTableSize) {
		return nil, nil, ErrSymbolTableTooLarge
	}
	if syms, err = SectionDataWithin(sec, MaxSymbolTableSize); err != nil {
		return nil, nil, err
	}
	if strs, err = SectionDataWithin(strtab, MaxSymbolTableSize); err != nil {
		return nil, nil, err
	}
	return syms, strs, nil
}

// storedPlainWithin reports whether s is stored uncompressed and within
// limit. No toolchain compresses a symbol or string table; a compressed one
// would be inflated in full before any of it is used.
func storedPlainWithin(s *elf.Section, limit uint64) bool {
	return s.Flags&elf.SHF_COMPRESSED == 0 && !strings.HasPrefix(s.Name, ".zdebug") && s.Size <= limit
}

// SymbolTableWithinCap reports whether debug/elf can materialise f's symbol
// table of type typ, the way Symbols, DynamicSymbols and cilium's
// link.Executable do, within the caps: the table and its string table are
// bounded in size, and so are the names copied out per symbol. The section
// is found by type, as debug/elf finds it, not by name. A file without such
// a table passes.
func SymbolTableWithinCap(f *elf.File, typ elf.SectionType) bool {
	if f.SectionByType(typ) == nil {
		return true
	}
	if typ == elf.SHT_DYNSYM {
		for _, vt := range symbolTableVersionSections {
			if s := f.SectionByType(vt); s != nil && !storedPlainWithin(s, MaxSymbolTableSize) {
				return false
			}
		}
	}
	var names uint64
	err := ForEachSymbol(f, typ, func(name []byte, _ Symbol) bool {
		names += uint64(len(name))
		return names <= MaxSymbolNameBytes
	})
	return err == nil && names <= MaxSymbolNameBytes
}

// SymbolTablesWithinCap reports whether every symbol table f carries is
// within SymbolTableWithinCap.
func SymbolTablesWithinCap(f *elf.File) bool {
	return SymbolTableWithinCap(f, elf.SHT_SYMTAB) && SymbolTableWithinCap(f, elf.SHT_DYNSYM)
}
