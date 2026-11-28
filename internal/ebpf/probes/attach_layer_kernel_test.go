//go:build bpf_loadtest && linux

package probes

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
)

func TestKernelThePoolLayoutLivesWithThePoolWaitEntrySite(t *testing.T) {
	prog := uprobeProgram(t)
	plain, _ := poolFixtures(t)
	realReturnSites(t, plain, "main.main")
	type poolValue struct{ NumOpen, MaxOpen, FreeConn uint32 }
	m := hashMap(t, poolValue{})
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{"uprobe_go_db_conn": prog, "uprobe_go_db_conn_ret": prog},
		Maps:     map[string]*ebpf.Map{"pool_offsets": m},
	}
	links := attachGoAcquireProbes(coll, plain, 70001)
	if len(links) < 2 {
		t.Fatalf("attached %d links, want the entry and its returns", len(links))
	}
	want, ok := resolvePoolFieldOffsets(plain, 0)
	if !ok {
		t.Fatal("fixture offsets did not resolve")
	}
	cookie := cookieOf(t, plain)
	var got poolValue
	if err := m.Lookup(&cookie, &got); err != nil || got != poolValue(want) {
		t.Fatalf("pool_offsets[%x] = %+v, %v; want %+v", cookie, got, err, want)
	}
	for _, l := range links {
		_ = l.Close()
	}
	if err := m.Lookup(&cookie, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("pool_offsets[%x] = %+v, %v after the site closed; want it deleted", cookie, got, err)
	}
}

func overlayMount(t *testing.T, lower string) string {
	t.Helper()
	dir := t.TempDir()
	upper, work, merged := filepath.Join(dir, "upper"), filepath.Join(dir, "work"), filepath.Join(dir, "merged")
	for _, d := range []string{upper, work, merged} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, work)
	if err := syscall.Mount("overlay", merged, "overlay", 0, opts); err != nil {
		t.Skipf("cannot mount overlayfs: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Unmount(merged, syscall.MNT_DETACH) })
	return merged
}

func TestKernelACopiedUpOverlayFileNeverSharesTheOriginalsUprobes(t *testing.T) {
	lower := t.TempDir()
	placeELF(t, filepath.Join(lower, "libssl.so.3"))
	victim := filepath.Join(overlayMount(t, lower), "libssl.so.3")
	tenantMount := overlayMount(t, lower)
	tenant := filepath.Join(tenantMount, "libssl.so.3")

	before, err := openExecutable(tenant)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := openExecutable(victim)
	if err != nil {
		t.Fatal(err)
	}
	if before.id != shared.id {
		t.Errorf("one lower file seen through two containers got two identities %+v and %+v; their uprobes would double", before.id, shared.id)
	}
	_ = before.Close()

	if err := os.Chmod(tenant, 0o700); err != nil {
		t.Fatal(err)
	}
	copied, err := openExecutable(tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = copied.Close() }()
	defer func() { _ = shared.Close() }()
	if copied.id == shared.id {
		t.Errorf("the tenant's copied-up file shares the victim's identity %+v; the victim's attach would reuse the tenant's uprobe", copied.id)
	}
}

func TestKernelAUprobeAtADebugFileOffsetAttachesFilteredToTheProcess(t *testing.T) {
	prog := uprobeProgram(t)
	exe, err := openExecutable(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = exe.Close() }()
	off, ok := goSymbolFileOffset(exe.Path(), "runtime.main")
	if !ok {
		t.Skip("runtime.main not resolved in the test binary")
	}
	l, err := exe.Uprobe("", prog, untrustedOffsetOptions(off, uint32(os.Getpid())))
	if err != nil {
		t.Fatalf("a PID-filtered uprobe did not attach: %v", err)
	}
	_ = l.Close()
}
