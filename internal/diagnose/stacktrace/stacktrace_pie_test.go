package stacktrace

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/procfs"
)

func TestTranslateAddr_StripsPIELoadBase(t *testing.T) {
	tests := []struct {
		name    string
		seg     loadSegment
		mapping exeMapping
		addr    uint64
		want    uint64
	}{
		{
			name:    "pie",
			seg:     loadSegment{off: 0x1000, vaddr: 0x1000, filesz: 0x4000},
			mapping: exeMapping{start: 0x555555555000, end: 0x555555559000, pgoff: 0x1000},
			addr:    0x555555555234,
			want:    0x1234,
		},
		{
			name:    "fixed-load",
			seg:     loadSegment{off: 0x1000, vaddr: 0x401000, filesz: 0x1000},
			mapping: exeMapping{start: 0x401000, end: 0x402000, pgoff: 0x1000},
			addr:    0x401234,
			want:    0x401234,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &stackResolver{
				segments: map[string][]loadSegment{"/bin/app": {tc.seg}},
				mappings: map[string][]exeMapping{"7|/bin/app": {tc.mapping}},
			}
			got, ok := r.translateAddr(7, "/bin/app", tc.addr)
			if !ok {
				t.Fatalf("translateAddr(%#x) failed, want %#x", tc.addr, tc.want)
			}
			if got != tc.want {
				t.Fatalf("translateAddr(%#x) = %#x, want %#x", tc.addr, got, tc.want)
			}
		})
	}
}

func TestTranslateAddr_MissReturnsFalse(t *testing.T) {
	r := &stackResolver{
		segments: map[string][]loadSegment{"/bin/app": {{off: 0x1000, vaddr: 0x1000, filesz: 0x1000}}},
		mappings: map[string][]exeMapping{"7|/bin/app": {{start: 0x555555555000, end: 0x555555556000, pgoff: 0x1000}}},
	}
	if _, ok := r.translateAddr(7, "/bin/app", 0xdeadbeef); ok {
		t.Fatal("translateAddr for an unmapped address must return ok=false")
	}
}

func TestExeMappings_ParsesProcMaps(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "42"), 0o755); err != nil {
		t.Fatal(err)
	}
	maps := "" +
		"555555554000-555555555000 r--p 00000000 08:01 100 /bin/app\n" +
		"555555555000-555555559000 r-xp 00001000 08:01 100 /bin/app\n" +
		"7ffff7d00000-7ffff7d22000 r-xp 00000000 08:01 200 /lib/libc.so.6\n" +
		"7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0 [stack]\n"
	if err := os.WriteFile(filepath.Join(base, "42", "maps"), []byte(maps), 0o644); err != nil {
		t.Fatal(err)
	}

	original := config.ProcBasePath
	config.ProcBasePath = base
	procfs.ResetForTesting()
	defer func() {
		config.ProcBasePath = original
		procfs.ResetForTesting()
	}()

	r := &stackResolver{}
	got := r.exeMappings(42, "/bin/app")
	if len(got) != 2 {
		t.Fatalf("got %d mappings for /bin/app, want 2: %+v", len(got), got)
	}
	exec := got[1]
	if exec.start != 0x555555555000 || exec.end != 0x555555559000 || exec.pgoff != 0x1000 {
		t.Fatalf("exec mapping = %+v, want start=0x555555555000 end=0x555555559000 pgoff=0x1000", exec)
	}
}

func TestLoadSegments_RealELF(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot resolve test executable: %v", err)
	}
	r := &stackResolver{}
	segs := r.loadSegments(exe)
	if len(segs) == 0 {
		t.Fatalf("no PT_LOAD segments parsed from %s", exe)
	}
	nonEmpty := false
	for _, s := range segs {
		if s.filesz > 0 {
			nonEmpty = true
		}
	}
	if !nonEmpty {
		t.Fatal("every PT_LOAD segment reported filesz=0")
	}
}
