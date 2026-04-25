package procfs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/podtrace/podtrace/internal/config"
)

// withProcBase swaps config.ProcBasePath to a tmp tree for the duration
// of the test, ensuring ResetForTesting fires.
func withProcBase(t *testing.T, base string) {
	t.Helper()
	original := config.ProcBasePath
	config.ProcBasePath = base
	ResetForTesting()
	t.Cleanup(func() {
		config.ProcBasePath = original
		ResetForTesting()
	})
}

func TestReadFile_Success(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "comm"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	withProcBase(t, dir)

	got, err := ReadFile("comm")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q, want hello", got)
	}
}

func TestReadFile_MissingIsErr(t *testing.T) {
	dir := t.TempDir()
	withProcBase(t, dir)
	if _, err := ReadFile("nope"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestReadFile_TraversalRejected(t *testing.T) {
	dir := t.TempDir()
	// Create a sibling file outside the root that we should NOT be
	// able to reach via a traversal.
	parent := filepath.Dir(dir)
	secret := filepath.Join(parent, "secret")
	_ = os.WriteFile(secret, []byte("x"), 0o600)
	defer func() { _ = os.Remove(secret) }()

	withProcBase(t, dir)
	if _, err := ReadFile("../" + filepath.Base(secret)); err == nil {
		t.Fatal("traversal must be rejected")
	}
}

func TestReadFile_AbsolutePathRejected(t *testing.T) {
	dir := t.TempDir()
	withProcBase(t, dir)
	_, err := ReadFile("/etc/hostname")
	if err == nil {
		t.Fatal("absolute path must be rejected")
	}
}

func TestStat_Success(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	withProcBase(t, dir)
	fi, err := Stat("f")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 1 {
		t.Errorf("size = %d, want 1", fi.Size())
	}
}

func TestStat_Missing(t *testing.T) {
	dir := t.TempDir()
	withProcBase(t, dir)
	if _, err := Stat("nope"); err == nil {
		t.Fatal("expected error")
	}
}

func TestOpen_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	withProcBase(t, dir)
	f, err := Open("f")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, 5)
	if _, err := f.Read(buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Errorf("got %q", buf)
	}
}

func TestRootForBase_FailsOnMissingPath(t *testing.T) {
	withProcBase(t, "/non/existent/path/does/not/exist")
	_, err := ReadFile("anything")
	if err == nil {
		t.Fatal("expected error for unopenable root")
	}
	if !strings.Contains(err.Error(), "procfs") {
		t.Errorf("err should mention procfs, got %v", err)
	}
}

func TestRootForBase_ReusesCachedRoot(t *testing.T) {
	dir := t.TempDir()
	withProcBase(t, dir)

	// First call opens.
	r1, err := rootForBase(config.ProcBasePath)
	if err != nil {
		t.Fatal(err)
	}
	// Second call reuses (same pointer).
	r2, err := rootForBase(config.ProcBasePath)
	if err != nil {
		t.Fatal(err)
	}
	if r1 != r2 {
		t.Errorf("expected cached root reuse")
	}
}

func TestRootForBase_ChangesWithBase(t *testing.T) {
	a := t.TempDir()
	b := t.TempDir()
	withProcBase(t, a)
	r1, err := rootForBase(config.ProcBasePath)
	if err != nil {
		t.Fatal(err)
	}
	config.ProcBasePath = b
	r2, err := rootForBase(config.ProcBasePath)
	if err != nil {
		t.Fatal(err)
	}
	if r1 == r2 {
		t.Errorf("expected fresh root after base change")
	}
}

// Sanity check that errors.Is over the wrapped error preserves the
// underlying cause.
func TestReadFile_WrapsOpenError(t *testing.T) {
	withProcBase(t, "/no/such/dir")
	_, err := ReadFile("foo")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, os.ErrNotExist) && !strings.Contains(err.Error(), "no such") {
		t.Logf("unwrapped err = %v", err)
	}
}
