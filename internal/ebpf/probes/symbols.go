package probes

import (
	"bytes"
	"debug/elf"

	"github.com/gma1k/podtrace/internal/ebpf/safeelf"
)

// symbolVaddr returns the virtual address of a defined symbol from either the
// static or dynamic symbol table.
func symbolVaddr(f *elf.File, name string) (uint64, bool) {
	for _, typ := range []elf.SectionType{elf.SHT_SYMTAB, elf.SHT_DYNSYM} {
		var vaddr uint64
		_ = safeelf.ForEachSymbol(f, typ, func(n []byte, sym safeelf.Symbol) bool {
			if sym.Value != 0 && string(n) == name {
				vaddr = sym.Value
				return false
			}
			return true
		})
		if vaddr != 0 {
			return vaddr, true
		}
	}
	return 0, false
}

// hasSymbolNamed reports whether either symbol table carries name, defined
// or not.
func hasSymbolNamed(f *elf.File, name string) bool {
	for _, typ := range []elf.SectionType{elf.SHT_DYNSYM, elf.SHT_SYMTAB} {
		found := false
		_ = safeelf.ForEachSymbol(f, typ, func(n []byte, _ safeelf.Symbol) bool {
			found = string(n) == name
			return !found
		})
		if found {
			return true
		}
	}
	return false
}

// nameContainsAll reports whether name contains every given substring.
func nameContainsAll(name []byte, subs ...string) bool {
	for _, s := range subs {
		if !bytes.Contains(name, []byte(s)) {
			return false
		}
	}
	return true
}

// findSymbolContaining returns the virtual address of the first defined
// function symbol whose name contains every given substring.
func findSymbolContaining(f *elf.File, subs ...string) (uint64, bool) {
	if found := findSymbolsContaining(f, 1, subs...); len(found) > 0 {
		return found[0], true
	}
	return 0, false
}

// findSymbolsContaining returns the virtual addresses of up to max defined
// function symbols in .symtab whose names contain every given substring.
func findSymbolsContaining(f *elf.File, max int, subs ...string) []uint64 {
	var out []uint64
	_ = safeelf.ForEachSymbol(f, elf.SHT_SYMTAB, func(n []byte, sym safeelf.Symbol) bool {
		if sym.Value == 0 || elf.ST_TYPE(sym.Info) != elf.STT_FUNC || !nameContainsAll(n, subs...) {
			return true
		}
		out = append(out, sym.Value)
		return len(out) < max
	})
	return out
}

// codeFileOffset maps the virtual address of an instruction to its file
// offset, accepting only an address the file itself backs inside an
// executable PT_LOAD segment.
func codeFileOffset(f *elf.File, vaddr uint64) (uint64, bool) {
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD || prog.Flags&elf.PF_X == 0 {
			continue
		}
		if vaddr >= prog.Vaddr && vaddr-prog.Vaddr < prog.Filesz {
			return vaddr - prog.Vaddr + prog.Off, true
		}
	}
	return 0, false
}
