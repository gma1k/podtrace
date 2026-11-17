package probes

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAFileChangedSinceItWasFirstSeenGetsANewIdentity(t *testing.T) {
	lib := filepath.Join(t.TempDir(), "libssl.so.3")
	placeELF(t, lib)
	before, ok := statFileID(lib)
	if !ok {
		t.Fatal("no identity")
	}
	mtime := time.Unix(0, before.mtimeNs)
	time.Sleep(10 * time.Millisecond)
	if err := os.Chmod(lib, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(lib, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	after, _ := statFileID(lib)
	if after.ino != before.ino || after.mtimeNs != before.mtimeNs || after.size != before.size {
		t.Fatalf("the fixture changed more than its change time: %+v vs %+v", before, after)
	}
	if after == before {
		t.Error("a file whose inode changed, as an overlayfs copy-up does, kept its identity; a victim would reuse the tenant's uprobe")
	}
}

func TestACopiedUpFileNeverSharesTheOriginalsUprobes(t *testing.T) {
	original := fileID{ino: 21818, size: 4096, mtimeNs: 7, ctimeNs: 100, buildID: "ab"}
	copiedUp := original
	copiedUp.ctimeNs = 200
	if usdtCookie(&executable{id: original, shared: true}, 0x40) == usdtCookie(&executable{id: copiedUp, shared: true}, 0x40) {
		t.Error("a copied-up file and its original got the same USDT site")
	}
	if (uprobeSite{file: original}) == (uprobeSite{file: copiedUp}) {
		t.Error("a copied-up file and its original share a uprobe site")
	}
}
