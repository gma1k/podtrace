package probes

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/safeelf"
)

func TestSplitProcRootFindsTheRootOfAProcessPath(t *testing.T) {
	orig := config.ProcBasePath
	t.Cleanup(func() { config.ProcBasePath = orig })
	config.ProcBasePath = "/host/proc"
	cases := []struct {
		path, root, rel string
		ok              bool
	}{
		{"/host/proc/42/root/usr/lib/libssl.so.3", "/host/proc/42/root", "usr/lib/libssl.so.3", true},
		{"/host/proc/42/root/../../etc/x", "", "", false},
		{"/host/proc/42/root", "", "", false},
		{"/host/proc/42/exe", "", "", false},
		{"/host/proc/self/root/lib", "", "", false},
		{"/host/proc/4a/root/lib", "", "", false},
		{"/host/proc//root/lib", "", "", false},
		{"/proc/self/fd/7", "", "", false},
		{"/host/proc/42/map_files/7f-80", "", "", false},
	}
	for _, c := range cases {
		root, rel, ok := splitProcRoot(c.path)
		if ok != c.ok || root != c.root || rel != c.rel {
			t.Errorf("splitProcRoot(%q) = (%q, %q, %v), want (%q, %q, %v)", c.path, root, rel, ok, c.root, c.rel, c.ok)
		}
	}
}

func TestADirectorySwappedForASymlinkAfterTheCheckCannotLeadTheAttachOutOfTheRootfs(t *testing.T) {
	f := newFakeProc(t, 41101)
	checked := f.writeContainerFile(t, "/usr/lib/libssl.so.3", "POD LIBSSL")
	if got := fileInProcRoot(f.pid, "/usr/lib/libssl.so.3"); got != checked {
		t.Fatalf("fileInProcRoot = %q, want %q", got, checked)
	}
	nodeLibs := filepath.Join(f.hostDir, "node-lib")
	placeELF(t, filepath.Join(nodeLibs, "libssl.so.3"))
	if err := os.RemoveAll(filepath.Join(f.root, "usr/lib")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(nodeLibs, filepath.Join(f.root, "usr/lib")); err != nil {
		t.Fatal(err)
	}

	if raw, _, err := safeelf.OpenRegular(checked); err == nil {
		_ = raw.Close()
	} else {
		t.Skipf("a plain open no longer follows the swapped symlink: %v", err)
	}
	if file, _, err := openAttachTarget(checked); err == nil {
		_ = file.Close()
		t.Fatal("the attach target resolved through the swapped symlink to the node's library")
	}
	if exe, err := openExecutable(checked); err == nil {
		_ = exe.Close()
		t.Fatal("openExecutable attached to a file outside the pod's rootfs")
	}
}

func TestAnAttachTargetFallsBackToAPlainOpenWithoutOpenat2(t *testing.T) {
	f := newFakeProc(t, 41102)
	checked := f.writeContainerFile(t, "/usr/lib/libssl.so.3", "POD LIBSSL")
	orig := openWithinRoot
	t.Cleanup(func() { openWithinRoot = orig })
	openWithinRoot = func(string, string) (*os.File, os.FileInfo, error) {
		return nil, nil, safeelf.ErrConfinementUnsupported
	}
	file, _, err := openAttachTarget(checked)
	if err != nil {
		t.Fatalf("openAttachTarget = %v, want the plain open a pre-5.6 kernel allows", err)
	}
	_ = file.Close()

	openWithinRoot = func(string, string) (*os.File, os.FileInfo, error) {
		return nil, nil, errors.New("refused")
	}
	if file, _, err := openAttachTarget(checked); err == nil {
		_ = file.Close()
		t.Error("a refused confined open fell back to a plain one")
	}
}
