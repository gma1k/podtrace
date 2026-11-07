package stacktrace

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/procfs"
)

func fakeMaps(t *testing.T, pid, maps string) {
	t.Helper()
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, pid), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, pid, "maps"), []byte(maps), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pointProcfsAt(t, base))
}

const deletedExeMaps = "555555554000-555555556000 r-xp 00001000 08:01 100 /tmp/busybox (deleted)\n" +
	"7f0000000000-7f0000100000 r-xp 00028000 08:01 200 /usr/lib/libc.so.6\n" +
	"7f0000200000-7f0000201000 rw-p 00000000 00:00 0 \n" +
	"7ffff7fc1000-7ffff7fc3000 r-xp 00000000 00:00 0 [vdso]\n"

func TestADeletedExecutableStillMatchesItsMappings(t *testing.T) {
	fakeMaps(t, "91", deletedExeMaps)

	got := (&stackResolver{}).exeMappings(91, "/tmp/busybox (deleted)")
	if len(got) != 1 || got[0].start != 0x555555554000 || got[0].pgoff != 0x1000 {
		t.Fatalf("mappings = %+v; readlink keeps \" (deleted)\" and the maps parser drops it, "+
			"so the two must be compared without it", got)
	}
}

func TestAnUnreadableMapsFileIsNotTakenAsUnmapped(t *testing.T) {
	t.Cleanup(pointProcfsAt(t, t.TempDir()))
	if name, unmapped := (&stackResolver{}).otherMappedFile(93, "/bin/app", 0x401000); name != "" || unmapped {
		t.Errorf("got (%q, %v); without maps the executable's own symbols must still be tried", name, unmapped)
	}
}

func TestAnAddressInALibraryIsNamedAfterTheLibrary(t *testing.T) {
	fakeMaps(t, "92", deletedExeMaps)
	r := &stackResolver{}

	for addr, want := range map[uint64]struct {
		name     string
		unmapped bool
	}{
		0x7f0000000123: {"libc.so.6", false},
		0x7ffff7fc1010: {"[vdso]", false},
		0x555555554100: {"", false},
		0x7f0000200010: {"", false},
		0xffffffff:     {"", true},
	} {
		name, unmapped := r.otherMappedFile(92, "/tmp/busybox (deleted)", addr)
		if name != want.name || unmapped != want.unmapped {
			t.Errorf("otherMappedFile(%#x) = (%q, %v), want (%q, %v)", addr, name, unmapped, want.name, want.unmapped)
		}
	}
}

func processWithLibrary(t *testing.T) uint32 {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "94"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(base, "94", "exe")); err != nil {
		t.Fatal(err)
	}
	maps := "00400000-00401000 r-xp 00000000 08:01 100 " + exe + "\n" +
		"7f0000000000-7f0000100000 r-xp 00028000 08:01 200 /usr/lib/libc.so.6\n"
	if err := os.WriteFile(filepath.Join(base, "94", "maps"), []byte(maps), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pointProcfsAt(t, base))
	return 94
}

func TestResolveNamesALibraryFrameAfterTheLibrary(t *testing.T) {
	pid := processWithLibrary(t)
	r := &stackResolver{cache: map[string]string{}}

	if got := r.resolve(context.Background(), pid, 0x7f0000000123); got != "libc.so.6@0x7f0000000123" {
		t.Errorf("resolve(libc frame) = %q, want libc.so.6@0x7f0000000123", got)
	}
	if got := r.resolve(context.Background(), pid, 0xffffffff); got != "0xffffffff" {
		t.Errorf("resolve(unmapped frame) = %q, want the raw address", got)
	}
}

func TestLoadSegmentsOfARegularFileThatIsNotELF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "script")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := readLoadSegments(path); got != nil {
		t.Errorf("readLoadSegments(non-ELF) = %v, want nil", got)
	}
}

func TestAStackStopsAtItsFirstEmptyFrame(t *testing.T) {
	pid := processWithLibrary(t)
	d := &mockDiagnostician{events: []*events.Event{{
		Type:      events.EventLockContention,
		PID:       pid,
		LatencyNS: 5_000_000,
		Stack:     []uint64{0x7f0000000123, 0, 0x7f0000000456},
	}}}

	got := GenerateStackTraceSectionWithContext(d, context.Background())
	if !strings.Contains(got, "#0 libc.so.6@0x7f0000000123") {
		t.Fatalf("want the first frame resolved:\n%s", got)
	}
	if strings.Contains(got, "#1") || strings.Contains(got, "0x7f0000000456") {
		t.Errorf("frames after the zero terminator were printed:\n%s", got)
	}
}

func TestAnAddressIsNamedInAMapsFileLargerThanReadFileAllows(t *testing.T) {
	dir := "/" + strings.Repeat("d", 3900)
	var b strings.Builder
	i := 0
	var last uint64
	for ; b.Len() <= procfs.MaxReadFileBytes; i++ {
		last = 0x1000 * uint64(i+1)
		fmt.Fprintf(&b, "%x-%x r-xp 00000000 08:01 %d %s/lib%d.so\n", last, last+0x1000, i+1, dir, i%2)
	}
	fakeMaps(t, "94", b.String())
	r := &stackResolver{}

	if name, unmapped := r.otherMappedFile(94, "/bin/app", last+0x10); name != fmt.Sprintf("lib%d.so", (i-1)%2) || unmapped {
		t.Fatalf("got (%q, %v) for the last mapping", name, unmapped)
	}
	ranges := r.allMaps["94|/bin/app"]
	if len(ranges) != i || ranges[0].name != "lib0.so" || ranges[1].name != "lib1.so" {
		t.Fatalf("cached %d ranges of %d", len(ranges), i)
	}
}

func TestExecutableMappingsWithoutAMapsFileAreEmpty(t *testing.T) {
	t.Cleanup(pointProcfsAt(t, t.TempDir()))
	if got := (&stackResolver{}).exeMappings(95, "/bin/app"); got != nil {
		t.Fatalf("mappings = %+v without a maps file", got)
	}
}
