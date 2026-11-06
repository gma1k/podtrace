package stacktrace

import (
	"runtime"
	"testing"
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
	if table == nil || table.goTable != nil {
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
