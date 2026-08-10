package probes

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/procmaps"
)

type fakeProc struct {
	procBase string
	pid      uint32
	root     string
	hostDir  string
}

func newFakeProc(t *testing.T, pid uint32) *fakeProc {
	t.Helper()

	procBase := t.TempDir()
	orig := config.ProcBasePath
	config.SetProcBasePath(procBase)
	t.Cleanup(func() { config.SetProcBasePath(orig) })

	root := filepath.Join(procBase, fmt.Sprintf("%d", pid), "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("create fake proc root: %v", err)
	}

	return &fakeProc{procBase: procBase, pid: pid, root: root, hostDir: t.TempDir()}
}

func (f *fakeProc) writeMaps(t *testing.T, content string) {
	t.Helper()
	p := filepath.Join(f.procBase, fmt.Sprintf("%d", f.pid), "maps")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write fake maps: %v", err)
	}
}

func (f *fakeProc) writeHostFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(f.hostDir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write host file: %v", err)
	}
	return p
}

func (f *fakeProc) writeContainerFile(t *testing.T, containerPath, content string) string {
	t.Helper()
	p := filepath.Join(f.root, containerPath)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("create container dir: %v", err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write container file: %v", err)
	}
	return p
}

func TestMappedFilesMatching_SpacedNameDoesNotEscapeToHost(t *testing.T) {
	f := newFakeProc(t, 41001)

	hostDecoy := f.writeHostFile(t, "libssl.so.3", "HOST LIBSSL")
	mapped := hostDecoy + " X"
	inContainer := f.writeContainerFile(t, mapped, "POD LIBSSL")

	f.writeMaps(t, fmt.Sprintf("7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 %s\n", mapped))

	got := mappedFilesMatching(f.pid, []string{"libssl.so.3"})

	for _, p := range got {
		if p == hostDecoy {
			t.Fatalf("resolved to the host file %q; a pod named its library %q to steer the agent out of its rootfs", hostDecoy, mapped)
		}
	}
	if len(got) != 1 || got[0] != inContainer {
		t.Fatalf("got %v, want [%s]", got, inContainer)
	}
}

func TestMappedFilesMatching_NoHostFallbackWhenAbsentFromRootfs(t *testing.T) {
	f := newFakeProc(t, 41002)

	hostOnly := f.writeHostFile(t, "libssl.so.3", "HOST LIBSSL")
	f.writeMaps(t, fmt.Sprintf("7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 %s\n", hostOnly))

	if got := mappedFilesMatching(f.pid, []string{"libssl.so.3"}); len(got) != 0 {
		t.Fatalf("got %v, want no candidates: the path is absent from the target rootfs and must not fall back to the host", got)
	}
}

func TestMappedFilesMatching_DeduplicatesSegmentsByInode(t *testing.T) {
	f := newFakeProc(t, 41003)

	lib := f.writeContainerFile(t, "/usr/lib/libssl.so.3", "POD LIBSSL")
	f.writeMaps(t, ""+
		"7f00000-7f01000 r--p 00000000 08:01 12 /usr/lib/libssl.so.3\n"+
		"7f01000-7f02000 r-xp 00001000 08:01 12 /usr/lib/libssl.so.3\n"+
		"7f02000-7f03000 r--p 00002000 08:01 12 /usr/lib/libssl.so.3\n"+
		"7f03000-7f04000 rw-p 00003000 08:01 12 /usr/lib/libssl.so.3\n")

	got := mappedFilesMatching(f.pid, []string{"libssl.so.3"})
	if len(got) != 1 || got[0] != lib {
		t.Fatalf("got %v, want [%s]", got, lib)
	}
}

func TestMappedFilesMatching_SkipsPseudoMappings(t *testing.T) {
	f := newFakeProc(t, 41004)

	f.writeMaps(t, ""+
		"7ffd000-7ffe000 rw-p 00000000 00:00 0 [stack]\n"+
		"7ffe000-7fff000 r-xp 00000000 00:00 0 [vdso]\n")

	if got := mappedFilesMatching(f.pid, []string{"[", "vdso"}); len(got) != 0 {
		t.Fatalf("got %v, want none", got)
	}
}

func TestResolveMappedFile_MapFilesWinsOverDisagreeingPathname(t *testing.T) {
	f := newFakeProc(t, 41005)

	hostDecoy := f.writeHostFile(t, "libssl.so.3", "HOST LIBSSL")
	real := f.writeContainerFile(t, "/usr/lib/real-libssl.so.3", "POD LIBSSL")

	claimed := filepath.Join(f.root, "usr", "lib", "libssl.so.3")
	if err := os.Symlink(hostDecoy, claimed); err != nil {
		t.Fatalf("create escaping symlink: %v", err)
	}

	const addrRange = "7f01000-7f02000"
	mapFiles := filepath.Join(f.procBase, fmt.Sprintf("%d", f.pid), "map_files")
	if err := os.MkdirAll(mapFiles, 0o755); err != nil {
		t.Fatalf("create map_files: %v", err)
	}
	if err := os.Symlink(real, filepath.Join(mapFiles, addrRange)); err != nil {
		t.Fatalf("create map_files link: %v", err)
	}

	e, ok := procmaps.ParseLine(addrRange + " r-xp 00000000 08:01 12 /usr/lib/libssl.so.3")
	if !ok {
		t.Fatal("procmaps.ParseLine rejected a valid line")
	}

	got := resolveMappedFile(f.pid, e)
	if got == claimed || got == hostDecoy {
		t.Fatalf("resolved to %q, which reaches the host decoy %q", got, hostDecoy)
	}
	if got != filepath.Join(mapFiles, addrRange) {
		t.Fatalf("got %q, want the map_files path %q", got, filepath.Join(mapFiles, addrRange))
	}
}

func TestResolveMappedFile_DeletedBackingFileUsesMapFiles(t *testing.T) {
	f := newFakeProc(t, 41006)

	real := f.writeContainerFile(t, "/opt/extracted.so", "TCNATIVE")

	const addrRange = "7f04000-7f05000"
	mapFiles := filepath.Join(f.procBase, fmt.Sprintf("%d", f.pid), "map_files")
	if err := os.MkdirAll(mapFiles, 0o755); err != nil {
		t.Fatalf("create map_files: %v", err)
	}
	if err := os.Symlink(real, filepath.Join(mapFiles, addrRange)); err != nil {
		t.Fatalf("create map_files link: %v", err)
	}

	e, ok := procmaps.ParseLine(addrRange + " r-xp 00000000 08:01 12 /tmp/libnetty_tcnative.so (deleted)")
	if !ok {
		t.Fatal("procmaps.ParseLine rejected a valid line")
	}

	if got := resolveMappedFile(f.pid, e); got != filepath.Join(mapFiles, addrRange) {
		t.Fatalf("got %q, want %q", got, filepath.Join(mapFiles, addrRange))
	}
}

func TestFileInProcRoot_RefusesRawHostPath(t *testing.T) {
	f := newFakeProc(t, 41007)

	hostOnly := f.writeHostFile(t, "libc.so.6", "HOST LIBC")

	if got := fileInProcRoot(f.pid, hostOnly); got != "" {
		t.Fatalf("got %q, want empty: the path exists only on the host, not in the target rootfs", got)
	}
}

func TestFindLibcViaProcessMaps_SpacedNameDoesNotEscapeToHost(t *testing.T) {
	f := newFakeProc(t, 41008)

	hostDecoy := f.writeHostFile(t, "libc.so.6", "HOST LIBC")
	mapped := hostDecoy + " X"
	inContainer := f.writeContainerFile(t, mapped, "POD LIBC")

	f.writeMaps(t, fmt.Sprintf("7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 %s\n", mapped))

	got := findLibcViaProcessMaps(f.pid)
	if got == hostDecoy {
		t.Fatalf("resolved libc to the host file %q", hostDecoy)
	}
	if got != inContainer {
		t.Fatalf("got %q, want %q", got, inContainer)
	}
}

func TestFindDBLibsViaProcessMaps_SpacedNameDoesNotEscapeToHost(t *testing.T) {
	f := newFakeProc(t, 41009)

	hostDecoy := f.writeHostFile(t, "libpq.so.5", "HOST LIBPQ")
	mapped := hostDecoy + " X"
	inContainer := f.writeContainerFile(t, mapped, "POD LIBPQ")

	f.writeMaps(t, fmt.Sprintf("7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 %s\n", mapped))

	got := findDBLibsViaProcessMaps(f.pid, []string{"libpq.so.5"})
	for _, p := range got {
		if p == hostDecoy {
			t.Fatalf("resolved to the host file %q", hostDecoy)
		}
	}
	if len(got) != 1 || got[0] != inContainer {
		t.Fatalf("got %v, want [%s]", got, inContainer)
	}
}

func TestFindGoBinaryViaProcessMaps_SpacedNameDoesNotEscapeToHost(t *testing.T) {
	f := newFakeProc(t, 41010)

	hostDecoy := f.writeHostFile(t, "app", "HOST BINARY")
	mapped := hostDecoy + " X"
	inContainer := f.writeContainerFile(t, mapped, "POD BINARY")

	f.writeMaps(t, fmt.Sprintf("7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 123456 %s\n", mapped))

	got := findGoBinaryViaProcessMaps(f.pid)
	if got == hostDecoy {
		t.Fatalf("resolved the Go binary to the host file %q", hostDecoy)
	}
	if got != inContainer {
		t.Fatalf("got %q, want %q", got, inContainer)
	}
}

func TestFindGoBinaryInProcess_RefusesRawHostPath(t *testing.T) {
	f := newFakeProc(t, 41011)

	hostOnly := f.writeHostFile(t, "app", "HOST BINARY")
	exe := filepath.Join(f.procBase, fmt.Sprintf("%d", f.pid), "exe")
	if err := os.Symlink(hostOnly, exe); err != nil {
		t.Fatalf("create exe symlink: %v", err)
	}

	if got := findGoBinaryInProcess(f.pid); got != "" {
		t.Fatalf("got %q, want empty: the target is absent from its own rootfs", got)
	}
}
