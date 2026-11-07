package procmaps

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/procfs"
)

func TestScanSkipsAnOverlongLineAndKeepsTheRest(t *testing.T) {
	long := "7f00-7f01 r-xp 00000000 08:01 7 /" + strings.Repeat("a", MaxLineBytes) + "\n"
	maps := "7e00-7e01 r--p 00000000 08:01 5 /lib/first.so\n" + long +
		"7f02-7f03 r-xp 00001000 08:02 9 /lib/last.so"

	var paths []string
	if err := Scan(strings.NewReader(maps), func(e Entry) bool {
		paths = append(paths, e.Path)
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[0] != "/lib/first.so" || paths[1] != "/lib/last.so" {
		t.Fatalf("paths = %q", paths)
	}
}

func TestScanStopsWhenVisitDeclines(t *testing.T) {
	maps := "7e00-7e01 r--p 00000000 08:01 5 /a\n7e01-7e02 r--p 00000000 08:01 6 /b\n"
	visited := 0
	if err := Scan(strings.NewReader(maps), func(Entry) bool {
		visited++
		return false
	}); err != nil || visited != 1 {
		t.Fatalf("visited %d, err %v", visited, err)
	}
}

func TestParseLineReadsDeviceAndInode(t *testing.T) {
	e, ok := ParseLine("7f00-7f01 r-xp 00001000 fd:01 1234567 /usr/lib/libssl.so.3")
	if !ok || e.Device != "fd:01" || e.Inode != 1234567 {
		t.Fatalf("entry = %+v, ok = %v", e, ok)
	}
	anon, ok := ParseLine("7f00-7f01 rw-p 00000000 00:00 0 ")
	if !ok || anon.Inode != 0 || anon.Named() {
		t.Fatalf("anonymous entry = %+v, ok = %v", anon, ok)
	}
}

func TestScanProcessReadsAMapsFileLargerThanReadFileAllows(t *testing.T) {
	base := t.TempDir()
	original := config.ProcBasePath
	config.ProcBasePath = base
	procfs.ResetForTesting()
	t.Cleanup(func() {
		config.ProcBasePath = original
		procfs.ResetForTesting()
	})

	dir := "/" + strings.Repeat("d", 3900)
	var b strings.Builder
	lines := 0
	for b.Len() <= procfs.MaxReadFileBytes {
		fmt.Fprintf(&b, "%x-%x r-xp 00000000 08:01 %d %s/lib%d.so\n", 0x1000*lines, 0x1000*lines+0x1000, lines+1, dir, lines)
		lines++
	}
	if err := os.MkdirAll(filepath.Join(base, "77"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "77", "maps"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	visited := 0
	if err := ScanProcess(77, func(e Entry) bool {
		visited++
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if visited != lines {
		t.Fatalf("visited %d of %d lines", visited, lines)
	}
}

func TestScanReportsAReadError(t *testing.T) {
	failure := errors.New("read failed")
	reader := io.MultiReader(strings.NewReader("7e00-7e01 r--p 00000000 08:01 5 /a\n"), iotest.ErrReader(failure))
	visited := 0
	err := Scan(reader, func(Entry) bool {
		visited++
		return true
	})
	if !errors.Is(err, failure) || visited != 1 {
		t.Fatalf("visited %d, err %v", visited, err)
	}
}

func TestScanSkipsAnOverlongLastLineWithoutANewline(t *testing.T) {
	maps := "7e00-7e01 r--p 00000000 08:01 5 /a\n7f00-7f01 r-xp 00000000 08:01 7 /" + strings.Repeat("b", 2*MaxLineBytes)
	visited := 0
	if err := Scan(strings.NewReader(maps), func(Entry) bool {
		visited++
		return true
	}); err != nil || visited != 1 {
		t.Fatalf("visited %d, err %v", visited, err)
	}
}

func TestScanProcessWithoutAMapsFile(t *testing.T) {
	base := t.TempDir()
	original := config.ProcBasePath
	config.ProcBasePath = base
	procfs.ResetForTesting()
	t.Cleanup(func() {
		config.ProcBasePath = original
		procfs.ResetForTesting()
	})
	if err := ScanProcess(78, func(Entry) bool { return true }); err == nil {
		t.Fatal("no error for a missing maps file")
	}
}
