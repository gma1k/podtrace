//go:build bpf_loadtest && linux

package tracer

import (
	"testing"

	"github.com/cilium/ebpf/link"

	"github.com/gma1k/podtrace/internal/ebpf/probes"
)

func attachLibraryProbe(t *testing.T, tr *Tracer, exe *link.Executable, symbol, program string, ret bool) {
	t.Helper()
	prog := tr.collection.Programs[program]
	if prog == nil {
		t.Fatalf("the object has no program %s", program)
	}
	var (
		l   link.Link
		err error
	)
	switch {
	case probes.UprobeMultiEnabled() && ret:
		l, err = exe.UretprobeMulti([]string{symbol}, prog, nil)
	case probes.UprobeMultiEnabled():
		l, err = exe.UprobeMulti([]string{symbol}, prog, nil)
	case ret:
		l, err = exe.Uretprobe(symbol, prog, nil)
	default:
		l, err = exe.Uprobe(symbol, prog, nil)
	}
	if err != nil {
		t.Fatalf("attach %s: %v", program, err)
	}
	t.Cleanup(func() { _ = l.Close() })
}
