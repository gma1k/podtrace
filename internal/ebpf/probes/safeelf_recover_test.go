package probes

import (
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/ebpf/safeelf"
)

func TestDWARFLoadsFromARealBinary(t *testing.T) {
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
	if _, err := safeelf.DWARF(f); err != nil {
		t.Errorf("a normal Go binary's DWARF must load within the caps: %v", err)
	}
}

func TestDWARFOfAnELFWithoutDebugSectionsIsAnError(t *testing.T) {
	f, err := emptyELF()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := safeelf.DWARF(f); err == nil {
		t.Error("an ELF with no debug sections yielded DWARF")
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
