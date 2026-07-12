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

// TestWriteFile_ModeGuard locks the invariant behind the G306 suppression:
// group/other read is allowed (0644 handoffs) but group/other write is
// rejected, regardless of call site.
func TestWriteFile_ModeGuard(t *testing.T) {
	dir := t.TempDir()

	allowed := []os.FileMode{0o600, 0o640, 0o644}
	for _, perm := range allowed {
		if err := WriteFile(filepath.Join(dir, "ok"), []byte("x"), perm); err != nil {
			t.Errorf("WriteFile with safe mode %#o rejected: %v", perm, err)
		}
	}

	rejected := []os.FileMode{0o666, 0o622, 0o777, 0o602}
	for _, perm := range rejected {
		err := WriteFile(filepath.Join(dir, "bad"), []byte("x"), perm)
		if !errors.Is(err, ErrUnsafeMode) {
			t.Errorf("WriteFile with group/other-writable mode %#o: got %v, want ErrUnsafeMode", perm, err)
		}
	}

	if err := WriteFileAtomic(filepath.Join(dir, "atomic"), []byte("x"), 0o666); !errors.Is(err, ErrUnsafeMode) {
		t.Errorf("WriteFileAtomic with 0666: got %v, want ErrUnsafeMode", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "atomic.tmp")); !os.IsNotExist(err) {
		t.Errorf("rejected atomic write left a .tmp residue")
	}
}

// TestWriteFileAtomic verifies the temp+rename write: the final file has the
// complete content, the correct perm, and no ".tmp" residue is left behind
// (the sidecar polls the final path and must never observe a partial file).
func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.txt")
	content := []byte("the full report body\n")

	if err := WriteFileAtomic(path, content, 0o644); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("content = %q, want %q", got, content)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("perm = %v, want 0644", info.Mode().Perm())
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file must not linger after rename, stat err = %v", err)
	}
}

// TestWriteFileAtomic_Overwrite confirms an existing file is replaced wholesale
// (rename semantics), not appended to.
func TestWriteFileAtomic_Overwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.txt")
	if err := WriteFileAtomic(path, []byte("first-longer-version"), 0o644); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := WriteFileAtomic(path, []byte("second"), 0o644); err != nil {
		t.Fatalf("second write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "second" {
		t.Errorf("content = %q, want %q", got, "second")
	}
}
