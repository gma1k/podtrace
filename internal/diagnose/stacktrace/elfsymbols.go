package stacktrace

import (
	"debug/elf"
	"debug/gosym"
	"fmt"
	"sort"
	"sync"
)

// symbolTable names instruction pointers from an executable's own symbols,
// so a frame can be resolved without addr2line on PATH.
type symbolTable struct {
	goTable *gosym.Table
	elfSyms []elf.Symbol // sorted by Value, only STT_FUNC with a size
}

// lookup returns the function containing addr, or "" when nothing covers it.
func (t *symbolTable) lookup(addr uint64) string {
	if t == nil {
		return ""
	}
	if t.goTable != nil {
		if fn := t.goTable.PCToFunc(addr); fn != nil && fn.Name != "" {
			return fn.Name
		}
	}
	i := sort.Search(len(t.elfSyms), func(i int) bool {
		return t.elfSyms[i].Value > addr
	})
	if i == 0 {
		return ""
	}
	s := t.elfSyms[i-1]
	if s.Size > 0 && addr >= s.Value+s.Size {
		return ""
	}
	return s.Name
}

// symbolTableCache keeps one parsed table per executable.
type symbolTableCache struct {
	mu     sync.Mutex
	tables map[string]*symbolTable
}

func (c *symbolTableCache) get(exePath string) *symbolTable {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tables == nil {
		c.tables = map[string]*symbolTable{}
	}
	if t, ok := c.tables[exePath]; ok {
		return t
	}
	t := loadSymbolTable(exePath)
	c.tables[exePath] = t
	return t
}

// loadSymbolTable reads whichever symbol source the binary carries, preferring
// Go's pclntab because it survives -ldflags=-s and names generics and methods
// the ELF symbol table renders less usefully.
func loadSymbolTable(exePath string) *symbolTable {
	f, err := openELFCapped(exePath)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	t := &symbolTable{}

	if pclntab := f.Section(".gopclntab"); pclntab != nil {
		if text := f.Section(".text"); text != nil {
			if pclnData, derr := pclntab.Data(); derr == nil {
				var symtabData []byte
				if st := f.Section(".gosymtab"); st != nil {
					symtabData, _ = st.Data()
				}
				if tbl, terr := gosym.NewTable(symtabData, gosym.NewLineTable(pclnData, text.Addr)); terr == nil {
					t.goTable = tbl
				}
			}
		}
	}

	if syms, serr := f.Symbols(); serr == nil {
		for _, s := range syms {
			if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Value == 0 || s.Name == "" {
				continue
			}
			t.elfSyms = append(t.elfSyms, s)
		}
		sort.Slice(t.elfSyms, func(i, j int) bool { return t.elfSyms[i].Value < t.elfSyms[j].Value })
	}

	if t.goTable == nil && len(t.elfSyms) == 0 {
		return nil
	}
	return t
}

// openELFCapped opens an executable for symbol reading, refusing anything that
// is not a well-formed ELF.
func openELFCapped(path string) (*elf.File, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open ELF %s: %w", path, err)
	}
	return f, nil
}
