//go:build linux

package safeelf

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func rootWithFile(t *testing.T, rel, content string) string {
	t.Helper()
	root := t.TempDir()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestOpenWithinRootOpensAFileInsideTheRoot(t *testing.T) {
	root := rootWithFile(t, "usr/lib/libssl.so.3", "POD")
	f, fi, err := OpenWithinRoot(root, "usr/lib/libssl.so.3")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if fi.Size() != 3 {
		t.Errorf("size = %d, want 3", fi.Size())
	}
}

func TestOpenWithinRootResolvesAnAbsoluteSymlinkInsideTheRoot(t *testing.T) {
	host := rootWithFile(t, "lib/libssl.so.3", "HOST")
	root := rootWithFile(t, filepath.Join(host, "lib/libssl.so.3"), "POD")
	if err := os.Symlink(host+"/lib", filepath.Join(root, "usr-lib")); err != nil {
		t.Fatal(err)
	}
	f, _, err := OpenWithinRoot(root, "usr-lib/libssl.so.3")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	data := make([]byte, 8)
	n, _ := f.Read(data)
	if string(data[:n]) != "POD" {
		t.Errorf("read %q through the symlink, want the root's own file", data[:n])
	}
}

func TestOpenWithinRootCannotClimbOutOfTheRoot(t *testing.T) {
	outside := rootWithFile(t, "secret", "HOST")
	root := t.TempDir()
	rel, err := filepath.Rel(root, filepath.Join(outside, "secret"))
	if err != nil {
		t.Fatal(err)
	}
	if f, _, err := OpenWithinRoot(root, rel); err == nil {
		_ = f.Close()
		t.Errorf("%s opened a file outside the root", rel)
	}
}

func TestOpenWithinRootRefusesSpecialAndMissingFiles(t *testing.T) {
	root := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(root, "fifo"), 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "dir"), 0o750); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"fifo", "dir", "missing"} {
		if f, _, err := OpenWithinRoot(root, rel); err == nil {
			_ = f.Close()
			t.Errorf("%s was opened", rel)
		}
	}
	if _, _, err := OpenWithinRoot(filepath.Join(root, "no-root"), "x"); err == nil {
		t.Error("a missing root was opened")
	}
}

func TestOpenWithinRootReportsAKernelWithoutOpenat2(t *testing.T) {
	orig := openat2
	t.Cleanup(func() { openat2 = orig })
	openat2 = func(int, string, *unix.OpenHow) (int, error) { return -1, unix.ENOSYS }
	if _, _, err := OpenWithinRoot(t.TempDir(), "x"); !errors.Is(err, ErrConfinementUnsupported) {
		t.Errorf("err = %v, want ErrConfinementUnsupported", err)
	}
}
