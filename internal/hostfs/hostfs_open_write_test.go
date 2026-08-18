package hostfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOpen_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data")
	if err := os.WriteFile(path, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, 7)
	n, err := f.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "payload" {
		t.Errorf("read %q, want %q", buf[:n], "payload")
	}
}

func TestOpen_RejectsRelative(t *testing.T) {
	if _, err := Open("relative/path"); !errors.Is(err, ErrInvalidPath) {
		t.Errorf("Open(relative) = %v, want ErrInvalidPath", err)
	}
}

func TestOpen_RejectsTraversal(t *testing.T) {
	if _, err := Open("/etc/../etc/passwd"); !errors.Is(err, ErrInvalidPath) {
		t.Errorf("Open(traversal) = %v, want ErrInvalidPath", err)
	}
}

func TestOpen_MissingFile(t *testing.T) {
	if _, err := Open("/no/such/hostfs/file"); err == nil {
		t.Error("Open on a missing file should error")
	} else if errors.Is(err, ErrInvalidPath) {
		t.Errorf("missing file should not be an ErrInvalidPath, got %v", err)
	}
}

func TestWriteFileAtomic_RejectsRelative(t *testing.T) {
	if err := WriteFileAtomic("relative", []byte("x"), 0o600); !errors.Is(err, ErrInvalidPath) {
		t.Errorf("WriteFileAtomic(relative) = %v, want ErrInvalidPath", err)
	}
}

func TestWriteFileAtomic_RenameFailureCleansTemp(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}

	err := WriteFileAtomic(target, []byte("body"), 0o600)
	if err == nil {
		t.Fatal("WriteFileAtomic must fail when the destination is an existing directory")
	}
	if _, statErr := os.Stat(target + ".tmp"); !os.IsNotExist(statErr) {
		t.Errorf("temp file must be removed after a rename failure, stat err = %v", statErr)
	}
}

func TestWriteFile_RefusesSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "artifact")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}

	err := WriteFile(link, []byte("redirected"), 0o600)
	if err == nil {
		t.Fatal("WriteFile through a symlink must be refused")
	}

	got, rerr := os.ReadFile(secret)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(got) != "original" {
		t.Errorf("symlink target was overwritten: %q", got)
	}
}

func TestWriteFile_PlainFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.txt")
	if err := WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := WriteFile(path, []byte("second"), 0o600); err != nil {
		t.Fatalf("WriteFile overwrite: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "second" {
		t.Errorf("content = %q, want %q", got, "second")
	}
}
