package probes

import (
	"strings"
	"testing"
)

func TestDWARFWithinCapRealBinary(t *testing.T) {
	bin := goFixtureBinary(t)
	f, err := openELFCapped(bin)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer func() { _ = f.Close() }()

	hasDebug := false
	for _, s := range f.Sections {
		if strings.HasPrefix(s.Name, ".debug_") || strings.HasPrefix(s.Name, ".zdebug_") {
			hasDebug = true
			break
		}
	}
	if !hasDebug {
		t.Skip("fixture binary was built without DWARF")
	}
	if !dwarfWithinCap(f) {
		t.Error("a normal Go binary's DWARF must be within cap")
	}
}

func TestDWARFWithinCapEmpty(t *testing.T) {
	f, err := emptyELF()
	if err != nil {
		t.Fatal(err)
	}
	if !dwarfWithinCap(f) {
		t.Error("an ELF with no debug sections is trivially within cap")
	}
}

func TestRecoverParseSwallowsPanic(t *testing.T) {
	reached := false
	func() {
		defer recoverParse("test-panic-site")
		panic("simulated malformed-binary panic")
	}()
	reached = true
	if !reached {
		t.Fatal("recoverParse did not swallow the panic; control never returned")
	}
}
