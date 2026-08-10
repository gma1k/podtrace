package probes

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
)

func mmapForTest(t *testing.T, path string) {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %q: %v", path, err)
	}
	t.Cleanup(func() { _ = f.Close() })

	data, err := syscall.Mmap(int(f.Fd()), 0, os.Getpagesize(), syscall.PROT_READ, syscall.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("mmap %q: %v", path, err)
	}
	t.Cleanup(func() { _ = syscall.Munmap(data) })
	runtime.KeepAlive(data)
}

func TestMappedFilesMatching_RealProcfsSpacedName(t *testing.T) {
	if config.ProcBasePath != "/proc" {
		t.Skipf("ProcBasePath is %q, not real procfs", config.ProcBasePath)
	}

	dir := t.TempDir()
	decoy := filepath.Join(dir, "libssl.so.3")
	spaced := decoy + " X"

	page := make([]byte, os.Getpagesize())
	if err := os.WriteFile(decoy, page, 0o644); err != nil {
		t.Fatalf("write decoy: %v", err)
	}
	if err := os.WriteFile(spaced, page, 0o644); err != nil {
		t.Fatalf("write spaced library: %v", err)
	}

	mmapForTest(t, spaced)

	maps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Fatalf("read own maps: %v", err)
	}
	if !strings.Contains(string(maps), spaced) {
		t.Fatalf("the mapping under test is absent from /proc/self/maps")
	}

	got := mappedFilesMatching(uint32(os.Getpid()), []string{"libssl.so.3"})
	if len(got) != 1 {
		t.Fatalf("got %v, want exactly one candidate", got)
	}

	decoyInfo, err := os.Stat(decoy)
	if err != nil {
		t.Fatalf("stat decoy: %v", err)
	}
	spacedInfo, err := os.Stat(spaced)
	if err != nil {
		t.Fatalf("stat spaced library: %v", err)
	}
	gotInfo, err := os.Stat(got[0])
	if err != nil {
		t.Fatalf("stat resolved %q: %v", got[0], err)
	}

	if os.SameFile(gotInfo, decoyInfo) {
		t.Fatalf("resolved %q to the decoy %q; the kernel does not escape the space in %q", got[0], decoy, spaced)
	}
	if !os.SameFile(gotInfo, spacedInfo) {
		t.Fatalf("resolved %q, which is neither the mapped file %q nor the decoy", got[0], spaced)
	}
}
