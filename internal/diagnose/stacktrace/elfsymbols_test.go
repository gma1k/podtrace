package stacktrace

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

const symFixtureSource = `package main

import "fmt"

//go:noinline
func TargetFunction(n int) int {
	return n * 3
}

func main() {
	fmt.Println(TargetFunction(7))
}
`

var (
	symOnce sync.Once
	symBin  string
	symErr  error
)

func buildSymFixture() {
	goTool, err := exec.LookPath("go")
	if err != nil {
		symErr = err
		return
	}
	dir, err := os.MkdirTemp("", "symfix")
	if err != nil {
		symErr = err
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(symFixtureSource), 0o644); err != nil {
		symErr = err
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module symfix\ngo 1.21\n"), 0o644); err != nil {
		symErr = err
		return
	}
	bin := filepath.Join(dir, "symfix")
	cmd := exec.Command(goTool, "build", "-o", bin, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		symErr = err
		_ = out
		return
	}
	symBin = bin
}

func symFixture(t *testing.T) string {
	t.Helper()
	symOnce.Do(buildSymFixture)
	if symErr != nil {
		t.Skipf("cannot build symbol fixture: %v", symErr)
	}
	return symBin
}

func TestAFunctionAddressResolvesToItsName(t *testing.T) {
	bin := symFixture(t)

	table := loadSymbolTable(bin)
	if table == nil {
		t.Fatal("no symbol table read from a binary built with symbols")
	}

	fn := table.goTable.LookupFunc("main.TargetFunction")
	if fn == nil {
		t.Fatal("fixture does not contain main.TargetFunction")
	}

	got := table.lookup(fn.Entry + 1)
	if !strings.Contains(got, "TargetFunction") {
		t.Errorf("lookup = %q, want main.TargetFunction.\n\nWithout this a report shows "+
			"binary@0xaddr, because the runtime image ships no addr2line to fall back on.", got)
	}
}

func TestAnAddressOutsideEveryFunctionResolvesToNothing(t *testing.T) {
	bin := symFixture(t)
	table := loadSymbolTable(bin)
	if table == nil {
		t.Skip("no symbol table")
	}

	if got := table.lookup(1); got != "" {
		t.Errorf("lookup(1) = %q, want empty; inventing a name for an address no "+
			"function covers is worse than printing the address", got)
	}
}

func TestAStrippedBinaryYieldsNoTable(t *testing.T) {
	bin := symFixture(t)
	stripped := filepath.Join(t.TempDir(), "stripped")

	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go tool")
	}
	src := filepath.Dir(bin)
	cmd := exec.Command(goTool, "build", "-ldflags=-s -w", "-o", stripped, ".")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot build stripped fixture: %v\n%s", err, out)
	}

	table := loadSymbolTable(stripped)
	if table != nil {
		if got := table.lookup(1); got != "" {
			t.Errorf("lookup(1) on a stripped binary = %q, want empty", got)
		}
	}
}

func TestTheSymbolTableIsParsedOncePerBinary(t *testing.T) {
	bin := symFixture(t)
	var c symbolTableCache

	first := c.get(bin)
	second := c.get(bin)

	if first != second {
		t.Error("the table was parsed twice for one binary.\n\nParsing a large Go binary " +
			"is expensive and every frame in a report tends to come from the same few " +
			"executables.")
	}
}

func TestAMissingBinaryCachesItsAbsence(t *testing.T) {
	var c symbolTableCache
	missing := filepath.Join(t.TempDir(), "not-here")

	if got := c.get(missing); got != nil {
		t.Errorf("get = %v, want nil for a path that does not exist", got)
	}
	if _, ok := c.tables[missing]; !ok {
		t.Error("the failure was not cached; a stripped or absent binary would be " +
			"re-parsed for every frame")
	}
}

func elfOnlyTable(syms ...elf.Symbol) *symbolTable {
	t := &symbolTable{elfSyms: syms}
	sort.Slice(t.elfSyms, func(i, j int) bool { return t.elfSyms[i].Value < t.elfSyms[j].Value })
	return t
}

func TestANonGoBinaryResolvesThroughTheELFSymbolTable(t *testing.T) {
	tbl := elfOnlyTable(
		elf.Symbol{Name: "handle_request", Value: 0x1000, Size: 0x80},
		elf.Symbol{Name: "parse_header", Value: 0x1100, Size: 0x40},
	)

	for addr, want := range map[uint64]string{
		0x1000: "handle_request",
		0x1040: "handle_request",
		0x1100: "parse_header",
		0x113f: "parse_header",
	} {
		if got := tbl.lookup(addr); got != want {
			t.Errorf("lookup(%#x) = %q, want %q.\n\nThis is the path for C and Rust "+
				"workloads, which have no .gopclntab; without it every frame in a non-Go "+
				"container stays a raw address.", addr, got, want)
		}
	}
}

func TestAnAddressBeforeTheFirstSymbolResolvesToNothing(t *testing.T) {
	tbl := elfOnlyTable(elf.Symbol{Name: "first", Value: 0x2000, Size: 0x10})

	if got := tbl.lookup(0x1fff); got != "" {
		t.Errorf("lookup below the first symbol = %q, want empty; attributing it to "+
			"\"first\" would name a function the address is not in", got)
	}
}

func TestAnAddressPastASymbolsEndResolvesToNothing(t *testing.T) {
	tbl := elfOnlyTable(elf.Symbol{Name: "small", Value: 0x3000, Size: 0x10})

	if got := tbl.lookup(0x3010); got != "" {
		t.Errorf("lookup past the symbol's size = %q, want empty.\n\nThe gap after a "+
			"function belongs to no symbol; the binary search finds the preceding entry "+
			"and its size is what rules the address out.", got)
	}
}

func TestASymbolWithNoSizeStillClaimsItsOwnAddress(t *testing.T) {
	tbl := elfOnlyTable(elf.Symbol{Name: "sizeless", Value: 0x4000})

	if got := tbl.lookup(0x4008); got != "sizeless" {
		t.Errorf("lookup = %q, want sizeless; a zero size means unknown extent, not "+
			"zero extent, so the nearest preceding symbol is the best answer available", got)
	}
}

func TestLookupOnANilTableIsSafe(t *testing.T) {
	var tbl *symbolTable
	if got := tbl.lookup(0x1000); got != "" {
		t.Errorf("lookup on a nil table = %q, want empty", got)
	}
}

func TestABinaryWithNeitherSymbolSourceYieldsNoTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-an-elf")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}

	if got := loadSymbolTable(path); got != nil {
		t.Errorf("loadSymbolTable on a shell script = %v, want nil; a table with no "+
			"sources would be consulted for every frame and never answer", got)
	}
}

func buildCFixture(t *testing.T, stripped bool) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		if cc, err = exec.LookPath("gcc"); err != nil {
			t.Skip("no C compiler available")
		}
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "prog.c")
	const code = `#include <stdio.h>
int compute_checksum(int n) { return n * 7 + 3; }
int main(void) { printf("%d\n", compute_checksum(5)); return 0; }
`
	if err := os.WriteFile(src, []byte(code), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	out := filepath.Join(dir, "prog")
	args := []string{"-O0", "-o", out, src}
	if stripped {
		args = append([]string{"-s"}, args...)
	}
	if o, err := exec.Command(cc, args...).CombinedOutput(); err != nil {
		t.Skipf("cannot build C fixture: %v\n%s", err, o)
	}
	return out
}

func TestARealCBinaryResolvesThroughELFSymbols(t *testing.T) {
	bin := buildCFixture(t, false)

	table := loadSymbolTable(bin)
	if table == nil {
		t.Fatal("no symbol table from an unstripped C binary")
	}
	if table.goTable != nil {
		t.Error("a C binary produced a Go symbol table")
	}

	var found bool
	for _, s := range table.elfSyms {
		if s.Name == "compute_checksum" {
			if got := table.lookup(s.Value); got != "compute_checksum" {
				t.Errorf("lookup at the symbol's own address = %q", got)
			}
			found = true
		}
	}
	if !found {
		t.Error("compute_checksum missing from the ELF symbols.\n\nThis is the whole " +
			"non-Go path: C and Rust workloads have no .gopclntab, so .symtab is the only " +
			"way their frames ever get a name.")
	}
}

func TestAStrippedCBinaryYieldsNoTableAtAll(t *testing.T) {
	bin := buildCFixture(t, true)

	if got := loadSymbolTable(bin); got != nil {
		t.Errorf("loadSymbolTable on a stripped C binary = %+v, want nil.\n\nA table with "+
			"neither source would be consulted for every frame and never answer; nil lets "+
			"the caller fall through to addr2line or the raw address.", got)
	}
}
