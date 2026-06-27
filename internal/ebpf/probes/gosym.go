package probes

import (
	"debug/elf"
	"debug/gosym"
)

// goSymbolFileOffset resolves the executable file offset of a Go function
// (e.g. "crypto/tls.(*Conn).Write") from the binary's .gopclntab.
func goSymbolFileOffset(exePath, symbol string) (offset uint64, ok bool) {
	f, err := elf.Open(exePath)
	if err != nil {
		return 0, false
	}
	defer func() { _ = f.Close() }()

	pcln := f.Section(".gopclntab")
	text := f.Section(".text")
	if pcln == nil || text == nil {
		return 0, false
	}
	pclnData, err := pcln.Data()
	if err != nil {
		return 0, false
	}

	var symtabData []byte
	if s := f.Section(".gosymtab"); s != nil {
		symtabData, _ = s.Data()
	}

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