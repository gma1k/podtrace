package stacktrace

import (
	"debug/elf"
	"testing"
)

func TestNoFrameIsNamedAfterTheEndOfTextMarker(t *testing.T) {
	bin := symFixture(t)
	f, err := elf.Open(bin)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	syms, err := f.Symbols()
	_ = f.Close()
	if err != nil {
		t.Fatalf("symbols: %v", err)
	}
	var etext uint64
	for _, s := range syms {
		if s.Name == "runtime.etext" {
			etext = s.Value
		}
	}
	if etext == 0 {
		t.Skip("fixture has no runtime.etext symbol")
	}

	table := loadSymbolTable(bin)
	for _, addr := range []uint64{etext + 1, etext + 0x10, etext + 0x10000} {
		if got := table.lookup(addr); got == "runtime.etext" {
			t.Errorf("lookup(%#x) = runtime.etext.\n\nIt is the linker's end-of-text marker, "+
				"not a function. As the last symbol with no size it claimed every address "+
				"above the code, and on kind it led a workload's profile.", addr)
		}
	}
}

func TestSizelessSymbolsAreBoundedByTheNextSymbolAndTheirSection(t *testing.T) {
	sections := []*elf.Section{
		{},
		{SectionHeader: elf.SectionHeader{Name: ".text", Addr: 0x1000, Size: 0x1000}},
	}
	got := boundSizelessSymbols([]elf.Symbol{
		{Name: "sized", Value: 0x1000, Size: 0x20, Section: 1},
		{Name: "mid", Value: 0x1100, Section: 1},
		{Name: "last", Value: 0x1800, Section: 1},
		{Name: "marker", Value: 0x2000, Section: 1},
	}, sections)

	want := map[string]uint64{"sized": 0x20, "mid": 0x700, "last": 0x800}
	if len(got) != len(want) {
		t.Fatalf("got %d symbols %+v, want %d: the marker at the section's end covers "+
			"nothing and must be dropped", len(got), got, len(want))
	}
	for _, s := range got {
		if s.Size != want[s.Name] {
			t.Errorf("%s size = %#x, want %#x", s.Name, s.Size, want[s.Name])
		}
	}
}

func TestASizelessSymbolWithNoBoundAtAllIsDropped(t *testing.T) {
	got := boundSizelessSymbols([]elf.Symbol{
		{Name: "only", Value: 0x5000, Section: elf.SHN_ABS},
	}, []*elf.Section{{}})
	if len(got) != 0 {
		t.Errorf("got %+v; a sizeless symbol with no following symbol and no section "+
			"would claim every address above it", got)
	}
}
