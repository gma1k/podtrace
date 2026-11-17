package probes

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestADeletedLibraryIsFoundThroughItsExecutableSegment(t *testing.T) {
	f := newFakeProc(t, 41201)
	extracted := f.writeContainerFile(t, "/tmp/.extracted/libssl.so.3", "OLD LIBSSL")
	const textRange = "7f01000-7f02000"
	mapFiles := filepath.Join(f.procBase, fmt.Sprintf("%d", f.pid), "map_files")
	if err := os.MkdirAll(mapFiles, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(extracted, filepath.Join(mapFiles, textRange)); err != nil {
		t.Fatal(err)
	}
	f.writeMaps(t, ""+
		"7f00000-7f01000 r--p 00000000 08:01 12 /usr/lib/libssl.so.3 (deleted)\n"+
		textRange+" r-xp 00001000 08:01 12 /usr/lib/libssl.so.3 (deleted)\n"+
		"7f02000-7f03000 r--p 00002000 08:01 12 /usr/lib/libssl.so.3 (deleted)\n")

	got := mappedFilesMatching(f.pid, []string{"libssl.so.3"})
	if len(got) != 1 || got[0] != filepath.Join(mapFiles, textRange) {
		t.Fatalf("got %v, want the executable segment's map_files entry; the read-only first segment marked the library done before it resolved", got)
	}
}
