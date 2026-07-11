package probes

import (
	"debug/elf"
	"debug/gosym"
	"encoding/binary"

	"golang.org/x/arch/x86/x86asm"
)

// goSymbolFileOffset resolves the executable file offset of a Go function
// (e.g. "crypto/tls.(*Conn).Write") from the binary's .gopclntab.
func goSymbolFileOffset(exePath, symbol string) (offset uint64, ok bool) {
	defer recoverParse("goSymbolFileOffset")
	f, err := openELFCapped(exePath)
	if err != nil {
		return 0, false
	}
	defer func() { _ = f.Close() }()

	pcln := f.Section(".gopclntab")
	text := f.Section(".text")
	if pcln == nil || text == nil {
		return 0, false
	}
	pclnData, err := sectionDataCapped(pcln)
	if err != nil {
		return 0, false
	}

	symtabData, _ := sectionDataCapped(f.Section(".gosymtab"))

	tbl, err := gosym.NewTable(symtabData, gosym.NewLineTable(pclnData, text.Addr))
	if err != nil {
		return 0, false
	}
	fn := tbl.LookupFunc(symbol)
	if fn == nil {
		return 0, false
	}

	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD {
			continue
		}
		if fn.Entry >= prog.Vaddr && fn.Entry < prog.Vaddr+prog.Memsz {
			return fn.Entry - prog.Vaddr + prog.Off, true
		}
	}
	return 0, false
}

// executableExportsSSL reports whether the ELF at path exposes the OpenSSL
// SSL_write symbol so the SSL_* uprobes can attach to the executable itself.
func executableExportsSSL(path string) (exports bool) {
	defer recoverParse("executableExportsSSL")
	f, err := openELFCapped(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	if symbolSectionWithinCap(f, ".dynsym") {
		if dyn, err := f.DynamicSymbols(); err == nil {
			for i := range dyn {
				if dyn[i].Name == "SSL_write" {
					return true
				}
			}
		}
	}
	if symbolSectionWithinCap(f, ".symtab") {
		if sym, err := f.Symbols(); err == nil {
			for i := range sym {
				if sym[i].Name == "SSL_write" {
					return true
				}
			}
		}
	}
	return false
}

// vaddrToFileOffset maps a virtual address to its executable file offset using
// the PT_LOAD segments.
func vaddrToFileOffset(f *elf.File, vaddr uint64) (uint64, bool) {
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD {
			continue
		}
		if vaddr >= prog.Vaddr && vaddr < prog.Vaddr+prog.Memsz {
			return vaddr - prog.Vaddr + prog.Off, true
		}
	}
	return 0, false
}

// goFuncReturnOffsets resolves the entry file offset of a Go function and the
// file offsets of every RET instruction within it, by scanning the function's
// machine code.
func goFuncReturnOffsets(exePath, symbol string) (entryOff uint64, retOffs []uint64, ok bool) {
	defer recoverParse("goFuncReturnOffsets")
	f, err := openELFCapped(exePath)
	if err != nil {
		return 0, nil, false
	}
	defer func() { _ = f.Close() }()

	if f.Machine != elf.EM_X86_64 && f.Machine != elf.EM_AARCH64 {
		return 0, nil, false
	}

	pcln := f.Section(".gopclntab")
	text := f.Section(".text")
	if pcln == nil || text == nil {
		return 0, nil, false
	}
	pclnData, err := sectionDataCapped(pcln)
	if err != nil {
		return 0, nil, false
	}
	symtabData, _ := sectionDataCapped(f.Section(".gosymtab"))
	tbl, err := gosym.NewTable(symtabData, gosym.NewLineTable(pclnData, text.Addr))
	if err != nil {
		return 0, nil, false
	}
	fn := tbl.LookupFunc(symbol)
	if fn == nil || fn.End <= fn.Entry {
		return 0, nil, false
	}

	entryOff, ok = vaddrToFileOffset(f, fn.Entry)
	if !ok {
		return 0, nil, false
	}

	textData, err := sectionDataCapped(text)
	if err != nil || fn.Entry < text.Addr {
		return 0, nil, false
	}
	start := fn.Entry - text.Addr
	end := fn.End - text.Addr
	if end > uint64(len(textData)) {
		return 0, nil, false
	}
	code := textData[start:end]

	var retPositions []uint64
	switch f.Machine {
	case elf.EM_X86_64:
		retPositions = x86ReturnPositions(code)
	case elf.EM_AARCH64:
		retPositions = arm64ReturnPositions(code)
	}
	for _, pos := range retPositions {
		if off, ok2 := vaddrToFileOffset(f, fn.Entry+pos); ok2 {
			retOffs = append(retOffs, off)
		}
	}
	return entryOff, retOffs, len(retOffs) > 0
}

// x86ReturnPositions decodes x86-64 code and returns the byte position of
// every RET instruction.
func x86ReturnPositions(code []byte) []uint64 {
	var out []uint64
	for pos := 0; pos < len(code); {
		inst, derr := x86asm.Decode(code[pos:], 64)
		if derr != nil || inst.Len == 0 {
			break
		}
		if inst.Op == x86asm.RET {
			out = append(out, uint64(pos))
		}
		pos += inst.Len
	}
	return out
}

// arm64RetInstruction is the sole encoding Go emits for a function return on
// arm64: RET (via x30).
const arm64RetInstruction = 0xd65f03c0

// arm64ReturnPositions scans fixed-width arm64 code and returns the byte
// position of every RET instruction.
func arm64ReturnPositions(code []byte) []uint64 {
	var out []uint64
	for pos := 0; pos+4 <= len(code); pos += 4 {
		if binary.LittleEndian.Uint32(code[pos:pos+4]) == arm64RetInstruction {
			out = append(out, uint64(pos))
		}
	}
	return out
}
