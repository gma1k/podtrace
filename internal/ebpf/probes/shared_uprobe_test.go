package probes

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type fakeLink struct {
	link.Link
	closed int
}

func (f *fakeLink) Close() error { f.closed++; return nil }

func newRegistry() *uprobeRegistry { return &uprobeRegistry{sites: map[uprobeSite]*sharedUprobe{}} }

func TestTheSameUprobeIsAttachedOnceAndClosedWithItsLastHolder(t *testing.T) {
	r := newRegistry()
	fl := &fakeLink{}
	attaches := 0
	attach := func() (link.Link, error) { attaches++; return fl, nil }
	site := uprobeSite{file: fileID{ino: 1}, symbol: "crypto/tls.(*Conn).Write"}

	a, err := r.acquire(site, attach)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := r.acquire(site, attach)
	if attaches != 1 {
		t.Fatalf("attached %d times; two containers of one image must share the uprobe or every call fires twice", attaches)
	}
	if err := a.Close(); err != nil || fl.closed != 0 {
		t.Fatalf("closing one holder closed the link (%d) while another still needs it", fl.closed)
	}
	_ = a.Close()
	if fl.closed != 0 {
		t.Fatal("a second Close of the same handle released another holder's reference")
	}
	_ = b.Close()
	if fl.closed != 1 || len(r.sites) != 0 {
		t.Errorf("closed %d times, %d sites left; the last holder must close the link", fl.closed, len(r.sites))
	}
	if err := r.release(site); err != nil {
		t.Errorf("releasing a site already gone = %v", err)
	}
}

func TestDifferentUprobesAreNotShared(t *testing.T) {
	r := newRegistry()
	attaches := 0
	attach := func() (link.Link, error) { attaches++; return &fakeLink{}, nil }
	p1, p2 := &ebpf.Program{}, &ebpf.Program{}
	base := uprobeSite{file: fileID{ino: 1}, symbol: "f", prog: p1}
	for _, s := range []uprobeSite{
		base,
		{file: fileID{ino: 2}, symbol: "f", prog: p1},
		{file: fileID{ino: 1}, symbol: "g", prog: p1},
		{file: fileID{ino: 1}, symbol: "f", prog: p2},
		{file: fileID{ino: 1}, symbol: "f", prog: p1, ret: true},
		{file: fileID{ino: 1}, symbol: "f", prog: p1, opts: link.UprobeOptions{Address: 8}},
		{file: fileID{ino: 1}, symbol: "f", prog: p1, opts: link.UprobeOptions{PID: 9}},
	} {
		if _, err := r.acquire(s, attach); err != nil {
			t.Fatal(err)
		}
	}
	if attaches != 7 {
		t.Errorf("attached %d times for 7 distinct uprobes", attaches)
	}
}

func TestAFailedAttachLeavesNothingBehind(t *testing.T) {
	r := newRegistry()
	boom := errors.New("no such symbol")
	if _, err := r.acquire(uprobeSite{symbol: "x"}, func() (link.Link, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if len(r.sites) != 0 {
		t.Error("a failed attach was recorded; the next holder would get a handle on nothing")
	}
}

func TestAFileIsIdentifiedByItsInodeNotItsPath(t *testing.T) {
	dir := t.TempDir()
	a, b, other := filepath.Join(dir, "a"), filepath.Join(dir, "b"), filepath.Join(dir, "other")
	if err := os.WriteFile(a, []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(a, b); err != nil {
		t.Skipf("no hard links here: %v", err)
	}
	if err := os.WriteFile(other, []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	ida, oka := statFileID(a)
	idb, okb := statFileID(b)
	ido, _ := statFileID(other)
	if !oka || !okb || ida != idb {
		t.Errorf("two paths to one file identified as %+v and %+v", ida, idb)
	}
	if ida == ido {
		t.Error("two files with the same contents were identified as one")
	}
	if _, ok := statFileID(filepath.Join(dir, "missing")); ok {
		t.Error("a missing file was given an identity")
	}
}

func TestAnExecutableWhoseIdentityIsUnknownIsNotShared(t *testing.T) {
	exe, err := openExecutable(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if !exe.shared || exe.id.ino == 0 {
		t.Errorf("the test binary got no identity: %+v", exe)
	}
	if _, err := openExecutable(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing file was opened")
	}
	unshared := &executable{Executable: exe.Executable}
	if _, err := unshared.Uprobe("definitely.NotAReal.Func", &ebpf.Program{}, nil); err == nil {
		t.Error("attaching to a missing symbol succeeded")
	}
	if len(sharedUprobes.sites) != 0 {
		t.Error("an unshared executable registered a site")
	}
}

type inodelessInfo struct{ fs.FileInfo }

func (inodelessInfo) Sys() any { return nil }

func TestAFileWithoutAnInodeHasNoIdentity(t *testing.T) {
	fi, err := os.Stat(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fileIDOf(inodelessInfo{fi}); ok {
		t.Error("a file with no inode was given an identity; its uprobes could be shared with an unrelated file")
	}
}
