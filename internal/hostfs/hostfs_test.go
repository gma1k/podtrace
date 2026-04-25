package hostfs

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestValidate(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"/usr/lib/libc.so.6", false},
		{"/proc/1234/root/lib/x86_64-linux-gnu/libc.so.6", false},
		{"relative/path", true},
		{"", true},
		{"/abs/with/../traversal", true},
		{"/abs/with/dot/./segment", false},
	}
	for _, c := range cases {
		err := validate(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("validate(%q) err=%v wantErr=%v", c.in, err, c.wantErr)
		}
	}
}

func TestStat_RealFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "x")
	if err := os.WriteFile(f, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	fi, err := Stat(f)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 2 {
		t.Errorf("size = %d, want 2", fi.Size())
	}
}

func TestStat_RejectsRelative(t *testing.T) {
	if _, err := Stat("relative"); !errors.Is(err, ErrInvalidPath) {
		t.Errorf("expected ErrInvalidPath, got %v", err)
	}
}

func TestStat_RejectsTraversal(t *testing.T) {
	if _, err := Stat("/etc/../etc/passwd"); !errors.Is(err, ErrInvalidPath) {
		t.Errorf("expected ErrInvalidPath, got %v", err)
	}
}

func TestIsRegularFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "f")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !IsRegularFile(f) {
		t.Error("expected true for regular file")
	}
	if IsRegularFile(dir) {
		t.Error("expected false for directory")
	}
	if IsRegularFile("/no/such/file/should/exist") {
		t.Error("expected false for missing path")
	}
	if IsRegularFile("relative-path") {
		t.Error("expected false for relative path")
	}
}

func TestWalkRegular(t *testing.T) {
	root := t.TempDir()
	for _, sub := range []string{"a", "b", "sub"} {
		if sub == "sub" {
			if err := os.MkdirAll(filepath.Join(root, sub), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, sub, "c"), []byte("3"), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(filepath.Join(root, sub), []byte(sub), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var seen []string
	err := WalkRegular(root, func(path string, info os.FileInfo) error {
		seen = append(seen, filepath.Base(path))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(seen)
	want := []string{"a", "b", "c"}
	if len(seen) != len(want) {
		t.Fatalf("got %v, want %v", seen, want)
	}
	for i, n := range want {
		if seen[i] != n {
			t.Errorf("seen[%d]=%q want %q", i, seen[i], n)
		}
	}
}

func TestWalkRegular_RejectsRelative(t *testing.T) {
	if err := WalkRegular("relative", func(string, os.FileInfo) error { return nil }); !errors.Is(err, ErrInvalidPath) {
		t.Errorf("expected ErrInvalidPath, got %v", err)
	}
}

func TestReadFile_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "data")
	if err := os.WriteFile(f, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q", got)
	}
}

func TestReadFile_RejectsRelative(t *testing.T) {
	if _, err := ReadFile("relative"); !errors.Is(err, ErrInvalidPath) {
		t.Errorf("expected ErrInvalidPath, got %v", err)
	}
}

func TestWriteFile_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "out")
	if err := WriteFile(f, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "data" {
		t.Errorf("got %q", got)
	}
}

func TestWriteFile_RejectsTraversal(t *testing.T) {
	if err := WriteFile("/tmp/../etc/passwd", []byte("x"), 0o600); !errors.Is(err, ErrInvalidPath) {
		t.Errorf("expected ErrInvalidPath, got %v", err)
	}
}
