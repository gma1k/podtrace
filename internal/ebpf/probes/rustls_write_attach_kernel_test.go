//go:build bpf_loadtest && linux

package probes

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestKernelRustlsWriteAttachesEntryAndReturnTogether(t *testing.T) {
	const pid = 4262
	syntheticProc(t, pid, loadableRustSections(rustlsWriteSymbol))
	prog := uprobeProgram(t)
	coll := &ebpf.Collection{Programs: map[string]*ebpf.Program{
		"uprobe_rustls_write":    prog,
		"uretprobe_rustls_write": prog,
		"uprobe_rustls_read":     {},
		"uretprobe_rustls_read":  {},
	}}
	links := AttachRustlsProbes(coll, pid)
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()
	if len(links) != 2 {
		t.Fatalf("attached %d links, want the write entry and its return probe", len(links))
	}
}

func TestKernelRustlsWriteEntryIsDroppedWithoutItsReturnProbe(t *testing.T) {
	const pid = 4263
	syntheticProc(t, pid, loadableRustSections(rustlsWriteSymbol))
	coll := &ebpf.Collection{Programs: map[string]*ebpf.Program{
		"uprobe_rustls_write":    uprobeProgram(t),
		"uretprobe_rustls_write": socketFilterProgram(t),
		"uprobe_rustls_read":     {},
		"uretprobe_rustls_read":  {},
	}}
	links := AttachRustlsProbes(coll, pid)
	for _, l := range links {
		_ = l.Close()
	}
	if len(links) != 0 {
		t.Fatalf("attached %d links, an entry probe whose return probe failed must not stay attached", len(links))
	}
}
