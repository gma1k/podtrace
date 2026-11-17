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

	"github.com/gma1k/podtrace/internal/config"
)

func TestKernelStalePoolOffsetsAreDeletedWhenResolutionFails(t *testing.T) {
	uprobeProgram(t)
	type poolValue struct{ NumOpen, MaxOpen, FreeConn uint32 }
	m := hashMap(t, poolValue{})
	const pid = uint32(70001)
	if err := m.Put(pid, poolValue{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	publishPoolOffsets(&ebpf.Collection{Maps: map[string]*ebpf.Map{"pool_offsets": m}}, filepath.Join(t.TempDir(), "missing"), pid)
	var got poolValue
	if err := m.Lookup(pid, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("a reused pid kept the previous process's offsets %+v (err %v)", got, err)
	}
}

func TestKernelStaleHTTP3PeerPathsAreDeletedWhenUnresolved(t *testing.T) {
	uprobeProgram(t)
	m := hashMap(t, h3PeerPaths{})
	const pid = uint32(70002)
	base := t.TempDir()
	orig := config.ProcBasePath
	config.ProcBasePath = base
	t.Cleanup(func() { config.ProcBasePath = orig })
	writeTestELF(t, filepath.Join(base, fmt.Sprint(pid), "exe"), []testSection{
		{name: ".text", typ: shtProgbits, flags: shfAlloc | shfExec, addr: testTextVA, data: make([]byte, 16), load: true},
	})
	stale := h3PeerPaths{}
	stale.Server.NSteps = 3
	if err := m.Put(pid, stale); err != nil {
		t.Fatal(err)
	}
	coll := &ebpf.Collection{Programs: map[string]*ebpf.Program{}, Maps: map[string]*ebpf.Map{"h3_peer_paths_map": m}}
	for _, l := range AttachGoHTTP3Probes(coll, pid) {
		_ = l.Close()
	}
	var got h3PeerPaths
	if err := m.Lookup(pid, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("a reused pid kept the previous process's peer paths %+v (err %v)", got, err)
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
