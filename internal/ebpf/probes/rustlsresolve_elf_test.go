package probes

import (
	"testing"
)

func TestElfIsRust(t *testing.T) {
	rust, err := elfFromSections([]fixtureSection{
		{name: ".comment", typ: 1, data: []byte("rustc version 1.70.0 (90c541806 2023-05-31)")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !elfIsRust(rust) {
		t.Error("expected rustc .comment to be detected as Rust")
	}

	gcc, err := elfFromSections([]fixtureSection{
		{name: ".comment", typ: 1, data: []byte("GCC: (Debian 12.2.0-14) 12.2.0")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if elfIsRust(gcc) {
		t.Error("a GCC .comment must not be detected as Rust")
	}

	none, err := emptyELF()
	if err != nil {
		t.Fatal(err)
	}
	if elfIsRust(none) {
		t.Error("an ELF with no .comment must not be detected as Rust")
	}
}

func TestFindSymbolContaining(t *testing.T) {
	bin := goFixtureBinary(t)
	f, err := openELFCapped(bin)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer func() { _ = f.Close() }()

	vaddr, ok := findSymbolContaining(f, "runtime.main")
	if !ok {
		t.Fatal("expected to find runtime.main via single substring")
	}
	if vaddr == 0 {
		t.Error("runtime.main vaddr is 0")
	}

	v2, ok := findSymbolContaining(f, "runtime", "main")
	if !ok || v2 == 0 {
		t.Error("expected to find a symbol containing both runtime and main")
	}

	if _, ok := findSymbolContaining(f, "runtime", "no_such_symbol_zzz"); ok {
		t.Error("expected no match when one substring is absent")
	}
	if _, ok := findSymbolContaining(f, "definitely_absent_symbol_zzz"); ok {
		t.Error("expected no match for an absent symbol")
	}
}

func TestFindSymbolContainingNoSymtab(t *testing.T) {
	f, err := emptyELF()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findSymbolContaining(f, "anything"); ok {
		t.Error("expected false when the ELF has no .symtab")
	}
}
