//go:build bpf_loadtest && linux

package probes

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/gma1k/podtrace/internal/config"
)

func grpcProc(t *testing.T, pid uint32, bin string) string {
	t.Helper()
	base := t.TempDir()
	orig := config.ProcBasePath
	config.ProcBasePath = base
	t.Cleanup(func() { config.ProcBasePath = orig })
	exe := filepath.Join(base, fmt.Sprint(pid), "exe")
	if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(bin, exe); err != nil {
		t.Fatal(err)
	}
	return exe
}

func TestKernelEveryProcessOfAGRPCBinarySharesOneLayoutUntilTheLastSiteCloses(t *testing.T) {
	bin := grpcFixtureBinary(t)
	grpcProc(t, 4270, bin)
	if err := os.MkdirAll(filepath.Join(config.ProcBasePath, "4271"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(bin, filepath.Join(config.ProcBasePath, "4271", "exe")); err != nil {
		t.Fatal(err)
	}
	prog := uprobeProgram(t)
	offsets := hashMap(t, grpcGoFieldOffsets{})
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"uprobe_grpc_go_write_header":   prog,
			"uprobe_grpc_go_server_headers": prog,
			"uprobe_grpc_go_client_headers": prog,
		},
		Maps: map[string]*ebpf.Map{"grpc_go_offsets": offsets},
	}
	first := AttachGoGRPCProbes(coll, 4270)
	second := AttachGoGRPCProbes(coll, 4271)
	if len(first) != 3 || len(second) != 3 {
		t.Fatalf("attached %d and %d grpc-go uprobes, want 3 each", len(first), len(second))
	}
	want, ok := resolveGRPCGoFieldOffsets(bin, 0)
	if !ok {
		t.Fatal("fixture offsets did not resolve")
	}
	cookie := cookieOf(t, bin)
	var got grpcGoFieldOffsets
	if err := offsets.Lookup(&cookie, &got); err != nil || got != want {
		t.Fatalf("grpc_go_offsets[%x] = %+v, %v; want %+v", cookie, got, err, want)
	}
	for _, l := range first {
		_ = l.Close()
	}
	if err := offsets.Lookup(&cookie, &got); err != nil {
		t.Fatalf("the layout went with the first process's links while the second still reads it: %v", err)
	}
	for _, l := range second {
		_ = l.Close()
	}
	if err := offsets.Lookup(&cookie, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("grpc_go_offsets[%x] = %+v, %v after every site closed; want it deleted", cookie, got, err)
	}
}

func TestKernelGRPCGoProbesAttachWhenTheMapRejectsTheLayout(t *testing.T) {
	bin := grpcFixtureBinary(t)
	grpcProc(t, 4272, bin)
	prog := uprobeProgram(t)
	offsets := hashMap(t, uint32(0))
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			"uprobe_grpc_go_write_header":   prog,
			"uprobe_grpc_go_server_headers": prog,
			"uprobe_grpc_go_client_headers": prog,
		},
		Maps: map[string]*ebpf.Map{"grpc_go_offsets": offsets},
	}
	links := AttachGoGRPCProbes(coll, 4272)
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()
	if len(links) != 3 {
		t.Fatalf("attached %d grpc-go uprobes, want 3 falling back to tuple pairing", len(links))
	}
	cookie := cookieOf(t, bin)
	var got uint32
	if err := offsets.Lookup(&cookie, &got); err == nil {
		t.Fatal("a map with the wrong value size received a layout")
	}
}
