package probes

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/podtrace/podtrace/internal/config"
)

func TestResolveSSLOffsetsNoDebugInfo(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skip("cannot resolve test executable")
	}
	if _, ok := resolveSSLOffsets(self, uint32(os.Getpid())); ok {
		t.Error("resolveSSLOffsets unexpectedly succeeded for a binary with no SSL debug info")
	}
}

func TestResolveSSLOffsetsViaBuildIDDebug(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		if cc, err = exec.LookPath("gcc"); err != nil {
			t.Skip("no C compiler available")
		}
	}
	objcopy, err := exec.LookPath("objcopy")
	if err != nil {
		t.Skip("objcopy not available")
	}
	strip, err := exec.LookPath("strip")
	if err != nil {
		t.Skip("strip not available")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "fake_ssl.c")
	if err := os.WriteFile(src, []byte(`
int SSL_read(void *s, void *b, int n)  { return n; }
int SSL_write(void *s, void *b, int n) { return n; }
int main(void) { return SSL_read(0,0,0) + SSL_write(0,0,0); }
`), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "fake_ssl")
	if out, err := exec.Command(cc, "-O0", "-no-pie", "-Wl,--build-id", "-o", bin, src).CombinedOutput(); err != nil {
		t.Skipf("compile failed (toolchain limitation): %v\n%s", err, out)
	}

	wantW, wantR, buildID := offsetsAndBuildID(t, bin)
	if buildID == "" {
		t.Skip("compiler did not emit a GNU build-id")
	}

	root := filepath.Join(dir, "root")
	debugDir := filepath.Join(root, "usr/lib/debug/.build-id", buildID[:2])
	if err := os.MkdirAll(debugDir, 0o755); err != nil {
		t.Fatal(err)
	}
	debugFile := filepath.Join(debugDir, buildID[2:]+".debug")
	if out, err := exec.Command(objcopy, "--only-keep-debug", bin, debugFile).CombinedOutput(); err != nil {
		t.Fatalf("objcopy: %v\n%s", err, out)
	}
	if out, err := exec.Command(strip, "--strip-all", bin).CombinedOutput(); err != nil {
		t.Fatalf("strip: %v\n%s", err, out)
	}

	if executableExportsSSL(bin) {
		t.Fatal("binary still exports SSL_write after strip; test fixture invalid")
	}

	origBase := config.ProcBasePath
	defer func() { config.ProcBasePath = origBase }()
	const pid = 4242
	config.ProcBasePath = dir
	if err := os.Rename(root, filepath.Join(dir, "4242", "root")); err != nil {
		_ = os.MkdirAll(filepath.Join(dir, "4242"), 0o755)
		if err := os.Rename(root, filepath.Join(dir, "4242", "root")); err != nil {
			t.Fatalf("stage rootfs: %v", err)
		}
	}

	off, ok := resolveSSLOffsets(bin, pid)
	if !ok {
		t.Fatal("resolveSSLOffsets failed to resolve via build-id debug file")
	}
	if off.source != "debug-buildid" {
		t.Errorf("source = %q, want debug-buildid", off.source)
	}
	if off.write != wantW {
		t.Errorf("SSL_write offset = %#x, want %#x", off.write, wantW)
	}
	if off.read != wantR {
		t.Errorf("SSL_read offset = %#x, want %#x", off.read, wantR)
	}
}

func offsetsAndBuildID(t *testing.T, path string) (w, r uint64, buildID string) {
	t.Helper()
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	buildID = elfBuildID(f)
	wv, okW := symbolVaddr(f, "SSL_write")
	rv, okR := symbolVaddr(f, "SSL_read")
	if !okW || !okR {
		t.Fatal("fixture binary missing SSL_write/SSL_read symbols")
	}
	w, okW = vaddrToFileOffset(f, wv)
	r, okR = vaddrToFileOffset(f, rv)
	if !okW || !okR {
		t.Fatal("could not map fixture symbol vaddr to file offset")
	}
	return w, r, buildID
}
