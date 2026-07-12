package tracer

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestPruneL7ProbesIfNoBPFLoop(t *testing.T) {
	t.Setenv("PODTRACE_FORCE_DISABLE_L7", "1")

	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"uprobe_h3_parse_headers": {
				Name: "uprobe_h3_parse_headers",
				Type: ebpf.Kprobe,
				Instructions: asm.Instructions{
					asm.Mov.Imm(asm.R1, 0),
					asm.FnLoop.Call(),
					asm.Return(),
				},
			},
			"kprobe_h2_tcp_recvmsg": {
				Name: "kprobe_h2_tcp_recvmsg",
				Type: ebpf.Kprobe,
				Instructions: asm.Instructions{
					asm.FnLoop.Call(),
					asm.Return(),
				},
			},
			"kprobe_tcp_connect": {
				Name: "kprobe_tcp_connect",
				Type: ebpf.Kprobe,
				Instructions: asm.Instructions{
					asm.Mov.Imm(asm.R0, 0),
					asm.Return(),
				},
			},
		},
	}

	pruneL7ProbesIfNoBPFLoop(spec)

	for _, gone := range []string{"uprobe_h3_parse_headers", "kprobe_h2_tcp_recvmsg"} {
		if _, ok := spec.Programs[gone]; ok {
			t.Errorf("program %q calls bpf_loop and must be pruned when the helper is absent", gone)
		}
	}
	if _, ok := spec.Programs["kprobe_tcp_connect"]; !ok {
		t.Error("core program kprobe_tcp_connect must be retained (no bpf_loop)")
	}
}

func TestPruneL7ProbesIfNoBPFLoop_NoOpWhenAvailable(t *testing.T) {
	if !bpfLoopAvailable() {
		t.Skip("bpf_loop not available on this host; prune-skip path not exercisable")
	}
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"uprobe_h3_parse_headers": {
				Name:         "uprobe_h3_parse_headers",
				Type:         ebpf.Kprobe,
				Instructions: asm.Instructions{asm.FnLoop.Call(), asm.Return()},
			},
		},
	}
	pruneL7ProbesIfNoBPFLoop(spec)
	if _, ok := spec.Programs["uprobe_h3_parse_headers"]; !ok {
		t.Error("L7 program must be retained when bpf_loop is available")
	}
}
