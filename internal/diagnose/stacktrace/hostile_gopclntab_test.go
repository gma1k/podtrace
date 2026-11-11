package stacktrace

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/gma1k/podtrace/internal/safeconv"
)

const hostileGopclntabCSource = `#include <stdio.h>
__attribute__((section(".gopclntab"), used))
const unsigned char hostile_pclntab[8 << 20] = {
	0xf1, 0xff, 0xff, 0xff, 0, 0, 1, 8,
	0, 0, 0, 0, 0, 0, 0, 0,
	0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0,
	0, 1, 0, 0, 0, 0, 0, 0,
	0, 1, 0, 0, 0, 0, 0, 0,
	0, 1, 0, 0, 0, 0, 0, 0,
	0, 1, 0, 0, 0, 0, 0, 0,
	0, 1, 0, 0, 0, 0, 0, 0,
	0, 1, 0, 0, 0, 0, 0, 0,
};
int compute_checksum(int n) { return n * 7 + 3; }
int main(void) { printf("%d\n", compute_checksum(5)); return 0; }
`

func TestAHostileGopclntabFileTableFallsBackToELFSymbolsWithoutAHugeAllocation(t *testing.T) {
	hostile := buildCProgram(t, hostileGopclntabCSource, false)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	table := loadSymbolTable(hostile)
	runtime.ReadMemStats(&after)

	if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<20 {
		t.Errorf("allocated %d MiB loading an 8 MiB pclntab whose file table claims 2^32-1 entries", grew>>20)
	}
	if table == nil || table.pcln != nil {
		t.Fatalf("table = %+v, want ELF symbols only", table)
	}
	var found bool
	for _, s := range table.elfSyms {
		if s.Name == "compute_checksum" {
			found = table.lookup(s.Value) == "compute_checksum"
		}
	}
	if !found {
		t.Error("the C symbols no longer resolve once a hostile pclntab is refused")
	}
}

func go116PclntabCSource(nfunc, nfiletab, size int) string {
	le := func(v int) string {
		return fmt.Sprintf("%d, %d, %d, %d, 0, 0, 0, 0", v&0xff, (v>>8)&0xff, (v>>16)&0xff, (v>>24)&0xff)
	}
	return fmt.Sprintf(`#include <stdio.h>
__attribute__((section(".gopclntab"), used))
const unsigned char hostile_pclntab[%d] = {
	0xfa, 0xff, 0xff, 0xff, 0, 0, 1, 8,
	%s,
	%s,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0x80, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0x80, 0, 0, 0, 0, 0, 0, 0,
};
int compute_checksum(int n) { return n * 7 + 3; }
int main(void) { printf("%%d\n", compute_checksum(5)); return 0; }
`, size, le(nfunc), le(nfiletab))
}

func TestAnOldLayoutPclntabClaimingAMillionFunctionsCostsOnlyItsFunctionTable(t *testing.T) {
	bin := buildCProgram(t, go116PclntabCSource(1<<20, 1<<18, 17<<20), false)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	table := loadSymbolTable(bin)
	runtime.GC()
	runtime.ReadMemStats(&after)
	if table == nil || table.pcln == nil {
		t.Fatal("a Go 1.16 pclntab did not get the lazy index")
		return
	}
	functab := int64(len(table.pcln.functab))
	if want := int64(2<<20+1) * 8; functab != want {
		t.Errorf("function table = %d bytes, want %d", functab, want)
	}
	retained := safeconv.Uint64ToInt64(after.HeapAlloc) - safeconv.Uint64ToInt64(before.HeapAlloc)
	if retained > functab+(4<<20) {
		t.Errorf("retained %d MiB for a %d MiB function table", retained>>20, functab>>20)
	}
	if budgeted := table.approxBytes(); budgeted < functab {
		t.Errorf("budgeted %d bytes for a %d byte function table", budgeted, functab)
	}
	for _, s := range table.elfSymbols(bin) {
		if s.Name == "compute_checksum" {
			if got := table.lookup(s.Value); got != "compute_checksum" {
				t.Errorf("lookup = %q, want the C symbol outside the claimed Go functions", got)
			}
			return
		}
	}
	t.Error("compute_checksum is not among the ELF symbols")
}

func TestSeveralHostileOldLayoutTablesStayCachedInsteadOfReparsing(t *testing.T) {
	loads := 0
	cache := &symbolTableCache{load: func(p string) *symbolTable { loads++; return loadSymbolTable(p) }}
	var bins []string
	for i := 0; i < 4; i++ {
		bins = append(bins, buildCProgram(t, go116PclntabCSource(1<<18, 1, 5<<20), false))
	}
	for round := 0; round < 3; round++ {
		for _, bin := range bins {
			if table := cache.get(bin); table == nil || table.pcln == nil {
				t.Fatal("no lazy index for a Go 1.16 pclntab")
			}
		}
	}
	if loads != len(bins) || cache.len() != len(bins) {
		t.Errorf("loaded %d times, cached %d; want each of the %d tables parsed once and kept", loads, cache.len(), len(bins))
	}
}
