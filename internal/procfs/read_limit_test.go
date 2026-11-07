package procfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadFileRefusesAFileOverTheLimit(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "huge"), make([]byte, MaxReadFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	withProcBase(t, dir)

	data, err := ReadFile("huge")
	if !errors.Is(err, ErrFileTooLarge) || data != nil {
		t.Fatalf("got %d bytes, err %v; want ErrFileTooLarge and no data", len(data), err)
	}
}

func TestReadFileLimitAcceptsAFileExactlyAtTheLimit(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	withProcBase(t, dir)

	if data, err := readFileLimit("cmdline", 10); err != nil || string(data) != "0123456789" {
		t.Fatalf("at the limit: %q, %v", data, err)
	}
	if _, err := readFileLimit("cmdline", 9); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("one byte over: err %v, want ErrFileTooLarge", err)
	}
}

func TestReadFileReportsAReadError(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "task"), 0o750); err != nil {
		t.Fatal(err)
	}
	withProcBase(t, dir)

	if data, err := ReadFile("task"); err == nil || data != nil {
		t.Fatalf("got %q, %v reading a directory", data, err)
	}
}
