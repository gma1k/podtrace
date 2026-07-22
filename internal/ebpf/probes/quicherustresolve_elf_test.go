package probes

import (
	"testing"
)

func TestFindSymbolsContaining(t *testing.T) {
	bin := goFixtureBinary(t)
	f, err := openELFCapped(bin)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer func() { _ = f.Close() }()

	four := findSymbolsContaining(f, 4, "net/http")
	if len(four) == 0 {
		t.Fatal("expected at least one net/http function symbol")
	}
	if len(four) > 4 {
		t.Errorf("returned %d symbols, want at most 4", len(four))
	}
	for i, v := range four {
		if v == 0 {
			t.Errorf("symbol %d has vaddr 0", i)
		}
	}

	one := findSymbolsContaining(f, 1, "net/http")
	if len(one) != 1 {
		t.Errorf("with max=1 got %d symbols, want 1", len(one))
	}

	if got := findSymbolsContaining(f, 4, "no_such_symbol_zzz"); got != nil {
		t.Errorf("expected nil for an absent substring, got %v", got)
	}
}

func TestFindSymbolsContainingNoSymtab(t *testing.T) {
	f, err := emptyELF()
	if err != nil {
		t.Fatal(err)
	}
	if got := findSymbolsContaining(f, 4, "anything"); got != nil {
		t.Errorf("expected nil when the ELF has no symbol table, got %v", got)
	}
}
