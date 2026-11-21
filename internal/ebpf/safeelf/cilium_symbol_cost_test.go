//go:build linux

package safeelf

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cilium/ebpf/link"
)

func distinctNameTables(symbols int, split bool) []rawSection {
	le := binary.LittleEndian
	strtab := []byte{0}
	table := make([]byte, elf.Sym64Size*(symbols+1))
	for i := 1; i <= symbols; i++ {
		e := table[i*elf.Sym64Size:]
		le.PutUint32(e[0:], u32(length(len(strtab))))
		strtab = append(append(strtab, fmt.Sprintf("f%07d", i)...), 0)
		e[4] = byte(elf.STT_FUNC)
		le.PutUint64(e[8:], 0x401000+uint64(i))
	}
	secs := []rawSection{
		{name: ".symtab", typ: elf.SHT_SYMTAB, link: 2, entsize: elf.Sym64Size, data: table},
		{name: ".strtab", typ: elf.SHT_STRTAB, data: strtab},
	}
	if split {
		half := table[:elf.Sym64Size*(symbols/2+1)]
		secs[0].data = half
		secs = append(secs, rawSection{name: ".dynsym", typ: elf.SHT_DYNSYM, link: 2, entsize: elf.Sym64Size, data: half})
	}
	return secs
}

func TestCiliumAllocatesNoMoreThanTheCapChargesForATableJustUnderIt(t *testing.T) {
	const nameLen = 8
	symbols := int(MaxMaterializedSymbolBytes/(elf.Sym64Size+materializedSymbolBytes+2*nameLen)) * 98 / 100
	for name, split := range map[string]bool{"static only": false, "static and dynamic": true} {
		raw := buildELF(elf.ELFCLASS64, distinctNameTables(symbols, split))
		path := filepath.Join(t.TempDir(), "near-cap")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		ef, err := elf.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		within := SymbolTablesWithinCap(ef)
		_ = ef.Close()
		if !within {
			t.Fatalf("%s: %d symbols just under the cap were refused", name, symbols)
		}
		exe, err := link.OpenExecutable(path)
		if err != nil {
			t.Fatal(err)
		}
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		_, _ = exe.Symbol(0)
		runtime.ReadMemStats(&after)
		if spent := after.TotalAlloc - before.TotalAlloc; spent > MaxMaterializedSymbolBytes {
			t.Errorf("%s: cilium allocated %d MiB materialising %d symbols the cap admits, over its %d MiB; "+
				"the cost model undercounts", name, spent>>20, symbols, MaxMaterializedSymbolBytes>>20)
		}
		runtime.KeepAlive(exe)
	}
}
