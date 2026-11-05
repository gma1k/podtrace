//go:build bpf_loadtest && linux

package probes

import (
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

func TestKernelAGRPCGoTargetGetsItsFramerOffsetsPublished(t *testing.T) {
	const pid = 4270
	bin := grpcFixtureBinary(t)
	grpcProc(t, pid, bin)
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
	links := AttachGoGRPCProbes(coll, pid)
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()
	if len(links) != 3 {
		t.Fatalf("attached %d grpc-go uprobes, want 3", len(links))
	}
	want, ok := resolveGRPCGoFieldOffsets(bin, 0)
	if !ok {
		t.Fatal("fixture offsets did not resolve")
	}
	var got grpcGoFieldOffsets
	key := uint32(pid)
	if err := offsets.Lookup(&key, &got); err != nil {
		t.Fatalf("no framer offsets published for the target: %v", err)
	}
	if got != want {
		t.Fatalf("published %+v, want %+v", got, want)
	}
}

func TestKernelAProcessWithoutGRPCGoDropsAStaleOffsetsEntry(t *testing.T) {
	offsets := hashMap(t, grpcGoFieldOffsets{})
	key := uint32(4271)
	if err := offsets.Put(&key, grpcGoFieldOffsets{LoopyFramer: 8, ServerFramer: 8, ClientFramer: 8}); err != nil {
		t.Fatal(err)
	}
	publishGRPCGoOffsets(&ebpf.Collection{Maps: map[string]*ebpf.Map{"grpc_go_offsets": offsets}}, goFixtureBinary(t), key)
	var got grpcGoFieldOffsets
	if err := offsets.Lookup(&key, &got); err == nil {
		t.Fatalf("offsets %+v of an earlier process with the same pid were left in place", got)
	}
}

func TestKernelGRPCGoOffsetsAreNeverPublishedForPidZero(t *testing.T) {
	offsets := hashMap(t, grpcGoFieldOffsets{})
	key := uint32(0)
	kept := grpcGoFieldOffsets{LoopyFramer: 8, ServerFramer: 8, ClientFramer: 8}
	if err := offsets.Put(&key, kept); err != nil {
		t.Fatal(err)
	}
	publishGRPCGoOffsets(&ebpf.Collection{Maps: map[string]*ebpf.Map{"grpc_go_offsets": offsets}}, grpcFixtureBinary(t), 0)
	var got grpcGoFieldOffsets
	if err := offsets.Lookup(&key, &got); err != nil || got != kept {
		t.Fatalf("pid 0 entry = %+v, %v; publishing for pid 0 must not touch the map", got, err)
	}
}

func TestKernelGRPCGoOffsetsSurviveAMapThatRejectsThem(t *testing.T) {
	offsets := hashMap(t, uint32(0))
	key := uint32(4272)
	publishGRPCGoOffsets(&ebpf.Collection{Maps: map[string]*ebpf.Map{"grpc_go_offsets": offsets}}, grpcFixtureBinary(t), key)
	var got uint32
	if err := offsets.Lookup(&key, &got); err == nil {
		t.Fatal("a map with the wrong value size must not receive an entry")
	}
}
