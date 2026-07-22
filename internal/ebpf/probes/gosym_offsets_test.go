package probes

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestVaddrToFileOffset(t *testing.T) {
	bin := goFixtureBinary(t)
	f, err := openELFCapped(bin)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer func() { _ = f.Close() }()

	vaddr, ok := symbolVaddr(f, "runtime.main")
	if !ok {
		t.Fatal("could not resolve runtime.main vaddr")
	}
	off, ok := vaddrToFileOffset(f, vaddr)
	if !ok {
		t.Fatal("vaddrToFileOffset failed for a valid text vaddr")
	}
	if off == 0 || off > vaddr {
		t.Errorf("file offset %#x implausible for vaddr %#x", off, vaddr)
	}

	if _, ok := vaddrToFileOffset(f, 0xffffffffffff0000); ok {
		t.Error("vaddrToFileOffset must fail for a vaddr outside every PT_LOAD")
	}
}

func TestGoSymbolFileOffsetMissingFile(t *testing.T) {
	if _, ok := goSymbolFileOffset(filepath.Join(t.TempDir(), "nope"), "runtime.main"); ok {
		t.Error("expected ok=false for a missing binary")
	}
}

func TestGoSymbolFileOffsetNoPclntab(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-pclntab")
	if err := os.WriteFile(path, buildELFWithSections(nil), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := goSymbolFileOffset(path, "runtime.main"); ok {
		t.Error("expected ok=false for an ELF without .gopclntab")
	}
}

func TestExecutableExportsSSLNegative(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("scans the test binary's symbol tables")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot find test executable: %v", err)
	}
	if executableExportsSSL(exe) {
		t.Error("a pure-Go test binary must not export SSL_write")
	}
	if executableExportsSSL(filepath.Join(t.TempDir(), "missing")) {
		t.Error("a missing binary must not report SSL exports")
	}
}

func TestExecutableExportsSSLPositive(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		if cc, err = exec.LookPath("gcc"); err != nil {
			t.Skip("no C compiler available")
		}
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "ssl.c")
	if err := os.WriteFile(src, []byte(`
int SSL_write(void *s, void *b, int n) { return n; }
int main(void) { return SSL_write(0, 0, 0); }
`), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "ssl_exe")
	if out, err := exec.Command(cc, "-O0", "-no-pie", "-o", bin, src).CombinedOutput(); err != nil {
		t.Skipf("compile failed: %v\n%s", err, out)
	}
	if !executableExportsSSL(bin) {
		t.Error("expected executableExportsSSL to detect the SSL_write symbol")
	}
}
