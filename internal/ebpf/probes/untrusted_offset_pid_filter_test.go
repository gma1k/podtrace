package probes

import (
	"debug/elf"
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type recordingTarget struct {
	refuse  bool
	entries []link.UprobeOptions
	returns []link.UprobeOptions
}

func (r *recordingTarget) Uprobe(_ string, _ *ebpf.Program, opts *link.UprobeOptions) (link.Link, error) {
	if r.refuse {
		return nil, errors.New("refused")
	}
	r.entries = append(r.entries, *opts)
	return namedFakeLink{name: "entry", closed: new([]string)}, nil
}

func (r *recordingTarget) Uretprobe(_ string, _ *ebpf.Program, opts *link.UprobeOptions) (link.Link, error) {
	if r.refuse {
		return nil, errors.New("refused")
	}
	r.returns = append(r.returns, *opts)
	return namedFakeLink{name: "return", closed: new([]string)}, nil
}

func TestEveryUprobeAtADebugFileOffsetIsFilteredToTheProcess(t *testing.T) {
	coll := placeholderPrograms("uprobe_SSL_write", "uretprobe_SSL_write", "uprobe_SSL_read", "uretprobe_SSL_read")
	target := &recordingTarget{}
	links := attachSSLByOffset(coll, target, 4321, sslOffsets{write: 0x100, read: 0x200})
	if len(links) != 4 || len(target.entries) != 2 || len(target.returns) != 2 {
		t.Fatalf("attached %d links (%d entries, %d returns), want 4 (2, 2)", len(links), len(target.entries), len(target.returns))
	}
	for _, opts := range append(target.entries, target.returns...) {
		if opts.PID != 4321 {
			t.Errorf("uprobe at %#x has PID %d, want 4321: unfiltered, it breaks every process mapping the file", opts.Address, opts.PID)
		}
	}
	if target.entries[0].Address != 0x100 || target.entries[1].Address != 0x200 {
		t.Errorf("entry addresses = %#x, %#x, want 0x100, 0x200", target.entries[0].Address, target.entries[1].Address)
	}
}

func TestADebugFileOffsetAttachSkipsMissingProgramsAndRefusals(t *testing.T) {
	if links := attachSSLByOffset(placeholderPrograms("uprobe_SSL_write"), &recordingTarget{refuse: true}, 1, sslOffsets{write: 1}); len(links) != 0 {
		t.Errorf("attached %d links from a target refusing every probe", len(links))
	}
	target := &recordingTarget{}
	if links := attachSSLByOffset(placeholderPrograms("uprobe_SSL_read"), target, 1, sslOffsets{read: 2}); len(links) != 1 {
		t.Errorf("attached %d links, want only the one program present", len(links))
	}
}

func TestRustOffsetsAreFilteredToTheProcessOnlyWhenADebugFileNamedThem(t *testing.T) {
	text := &elf.Prog{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X, Off: 0x1000, Vaddr: 0x401000, Filesz: 0x100, Memsz: 0x100}}
	src := rustSymbolSource{target: &elf.File{Progs: []*elf.Prog{text}}, pid: 77}

	own := src.offsets([]uint64{0x401010, 0x900000}, false)
	if len(own) != 1 || own[0].Address != 0x1010 || own[0].PID != 0 {
		t.Errorf("offsets from the binary's own symbols = %+v, want one shared probe at 0x1010", own)
	}
	debug := src.offsets([]uint64{0x401020}, true)
	if len(debug) != 1 || debug[0].Address != 0x1020 || debug[0].PID != 77 {
		t.Errorf("offsets from a debug file = %+v, want one probe at 0x1020 filtered to pid 77", debug)
	}
}
