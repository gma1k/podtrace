package stacktrace

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/procfs"
)

func TestIsSortedAndSortKsyms(t *testing.T) {
	sorted := []ksym{
		{Addr: 0x1000, Name: "a"},
		{Addr: 0x2000, Name: "b"},
		{Addr: 0x3000, Name: "c"},
	}
	if !isSorted(sorted) {
		t.Fatalf("isSorted returned false for an already-sorted slice")
	}

	withEqual := []ksym{
		{Addr: 0x1000, Name: "a"},
		{Addr: 0x1000, Name: "b"},
	}
	if !isSorted(withEqual) {
		t.Fatalf("isSorted returned false for a slice with equal addresses")
	}

	unsorted := []ksym{
		{Addr: 0x3000, Name: "c"},
		{Addr: 0x1000, Name: "a"},
		{Addr: 0x2000, Name: "b"},
	}
	if isSorted(unsorted) {
		t.Fatalf("isSorted returned true for an unsorted slice")
	}

	sortKsyms(unsorted)
	if !isSorted(unsorted) {
		t.Fatalf("sortKsyms did not sort the slice: %+v", unsorted)
	}
	wantOrder := []string{"a", "b", "c"}
	for i, want := range wantOrder {
		if unsorted[i].Name != want {
			t.Errorf("sortKsyms order: index %d = %q, want %q", i, unsorted[i].Name, want)
		}
	}
}

// writeKallsyms creates a temp dir holding a fake "kallsyms" file with the
// given content, points config.ProcBasePath at it, and resets the procfs
// root. It returns a cleanup func that restores the previous state.
func writeKallsyms(t *testing.T, content string) func() {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "kallsyms"), []byte(content), 0o644); err != nil {
		t.Fatalf("write fake kallsyms: %v", err)
	}
	return pointProcfsAt(t, dir)
}

// pointProcfsAt sets config.ProcBasePath to dir and resets the procfs root,
// returning a cleanup func that restores the prior path and resets again.
func pointProcfsAt(t *testing.T, dir string) func() {
	t.Helper()
	original := config.ProcBasePath
	config.ProcBasePath = dir
	procfs.ResetForTesting()
	return func() {
		config.ProcBasePath = original
		procfs.ResetForTesting()
	}
}

func TestKallsymsLoadAndResolve(t *testing.T) {
	t.Run("sorted", func(t *testing.T) {
		content := "ffffffff81000000 T _stext\n" +
			"ffffffff81000100 T do_something\n" +
			"0000000000000000 t hidden\n" +
			"badline\n"
		cleanup := writeKallsyms(t, content)
		defer cleanup()

		k := &kallsymsLookup{}

		if got := k.Resolve(0); got != "" {
			t.Errorf("Resolve(0) = %q, want \"\"", got)
		}
		if got := k.Resolve(0xffffffff81000010); got != "_stext+0x10" {
			t.Errorf("Resolve(0xffffffff81000010) = %q, want %q", got, "_stext+0x10")
		}
		if got := k.Resolve(0xffffffff81000000); got != "_stext+0x0" {
			t.Errorf("exact-match Resolve = %q, want %q", got, "_stext+0x0")
		}
		if got := k.Resolve(0xffffffff81000100); got != "do_something+0x0" {
			t.Errorf("Resolve(do_something addr) = %q, want %q", got, "do_something+0x0")
		}
		if got := k.Resolve(0xffffffff82000000); got != "" {
			t.Errorf("Resolve(above maxAddr) = %q, want \"\"", got)
		}
		if !k.loaded {
			t.Errorf("expected loaded=true after a successful load")
		}
		if len(k.syms) != 2 {
			t.Errorf("expected 2 symbols loaded (addr-0 skipped), got %d", len(k.syms))
		}
	})

	t.Run("unsorted", func(t *testing.T) {
		content := "ffffffff81000200 T third\n" +
			"ffffffff81000000 T first\n" +
			"ffffffff81000100 T second\n"
		cleanup := writeKallsyms(t, content)
		defer cleanup()

		k := &kallsymsLookup{}

		if got := k.Resolve(0xffffffff81000004); got != "first+0x4" {
			t.Errorf("Resolve(first+4) = %q, want %q", got, "first+0x4")
		}
		if got := k.Resolve(0xffffffff81000110); got != "second+0x10" {
			t.Errorf("Resolve(second+0x10) = %q, want %q", got, "second+0x10")
		}
		if got := k.Resolve(0xffffffff81000200); got != "third+0x0" {
			t.Errorf("Resolve(third) = %q, want %q", got, "third+0x0")
		}
		if !isSorted(k.syms) {
			t.Errorf("load() did not sort symbols: %+v", k.syms)
		}
	})
}

func TestKallsymsLoadMissing(t *testing.T) {
	dir := t.TempDir()
	cleanup := pointProcfsAt(t, dir)
	defer cleanup()

	k := &kallsymsLookup{}
	if got := k.Resolve(0xffffffff81000010); got != "" {
		t.Errorf("Resolve with missing kallsyms = %q, want \"\"", got)
	}
	if k.loaded {
		t.Errorf("expected loaded=false when kallsyms is missing")
	}
}
