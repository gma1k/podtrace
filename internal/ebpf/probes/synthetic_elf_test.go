package probes

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/gma1k/podtrace/internal/config"
)

type testSection struct {
	name    string
	typ     uint32
	flags   uint64
	addr    uint64
	data    []byte
	link    uint32
	entsize uint64
}

const (
	shtProgbits = 1
	shtSymtab   = 2
	shtStrtab   = 3
	shtNote     = 7
	shfAlloc    = 2
	shfExec     = 4
	testTextVA  = 0x401000
)

func writeTestELF(t *testing.T, path string, sections []testSection) {
	t.Helper()
	le := binary.LittleEndian
	shstr := []byte{0}
	nameIdx := make([]uint32, len(sections)+1)
	for i, s := range sections {
		nameIdx[i] = uint32(len(shstr))
		shstr = append(shstr, s.name+"\x00"...)
	}
	nameIdx[len(sections)] = uint32(len(shstr))
	shstr = append(shstr, ".shstrtab\x00"...)
	all := append(append([]testSection{}, sections...), testSection{typ: shtStrtab, data: shstr})

	buf := make([]byte, 64)
	offs := make([]uint64, len(all))
	for i, s := range all {
		for len(buf)%8 != 0 {
			buf = append(buf, 0)
		}
		offs[i] = uint64(len(buf))
		buf = append(buf, s.data...)
	}
	for len(buf)%8 != 0 {
		buf = append(buf, 0)
	}
	shoff := uint64(len(buf))
	shnum := len(all) + 1
	buf = append(buf, make([]byte, shnum*64)...)

	copy(buf, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	le.PutUint16(buf[16:], 2)
	le.PutUint16(buf[18:], 62)
	le.PutUint32(buf[20:], 1)
	le.PutUint64(buf[40:], shoff)
	le.PutUint16(buf[52:], 64)
	le.PutUint16(buf[54:], 56)
	le.PutUint16(buf[58:], 64)
	le.PutUint16(buf[60:], uint16(shnum))
	le.PutUint16(buf[62:], uint16(shnum-1))
	for i, s := range all {
		h := buf[int(shoff)+(i+1)*64:]
		le.PutUint32(h[0:], nameIdx[i])
		le.PutUint32(h[4:], s.typ)
		le.PutUint64(h[8:], s.flags)
		le.PutUint64(h[16:], s.addr)
		le.PutUint64(h[24:], offs[i])
		le.PutUint64(h[32:], uint64(len(s.data)))
		le.PutUint32(h[40:], s.link)
		if s.typ == shtSymtab {
			le.PutUint32(h[44:], 1)
		}
		le.PutUint64(h[48:], 1)
		le.PutUint64(h[56:], s.entsize)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf, 0o755); err != nil {
		t.Fatal(err)
	}
}

func rustLikeSections(funcs ...string) []testSection {
	le := binary.LittleEndian
	strtab := []byte{0}
	symtab := make([]byte, 24)
	for i, fn := range funcs {
		sym := make([]byte, 24)
		le.PutUint32(sym[0:], uint32(len(strtab)))
		sym[4] = 0x12
		le.PutUint16(sym[6:], 1)
		le.PutUint64(sym[8:], testTextVA+uint64(i)*16)
		le.PutUint64(sym[16:], 16)
		symtab = append(symtab, sym...)
		strtab = append(strtab, fn+"\x00"...)
	}
	return []testSection{
		{name: ".text", typ: shtProgbits, flags: shfAlloc | shfExec, addr: testTextVA, data: make([]byte, 16*len(funcs)+16)},
		{name: ".comment", typ: shtProgbits, data: []byte("rustc version 1.90.0\x00")},
		{name: ".symtab", typ: shtSymtab, data: symtab, link: 4, entsize: 24},
		{name: ".strtab", typ: shtStrtab, data: strtab},
	}
}

func stapsdtNote(pc uint64, provider, name string) []byte {
	le := binary.LittleEndian
	desc := make([]byte, 24)
	le.PutUint64(desc[0:], pc)
	desc = append(desc, provider+"\x00"+name+"\x00"+"-4@%edi\x00"...)
	for len(desc)%4 != 0 {
		desc = append(desc, 0)
	}
	note := make([]byte, 12)
	le.PutUint32(note[0:], 8)
	le.PutUint32(note[4:], uint32(len(desc)))
	le.PutUint32(note[8:], 3)
	note = append(note, "stapsdt\x00"...)
	return append(note, desc...)
}

func syntheticProc(t *testing.T, pid uint32, sections []testSection) {
	t.Helper()
	base := t.TempDir()
	orig := config.ProcBasePath
	config.ProcBasePath = base
	t.Cleanup(func() { config.ProcBasePath = orig })
	writeTestELF(t, filepath.Join(base, fmt.Sprint(pid), "exe"), sections)
}

func TestRustProbesOpenARustBinaryWithTheirSymbols(t *testing.T) {
	const pid = 4250
	syntheticProc(t, pid, rustLikeSections(
		"_ZN6rustls4conn6Writer5write17h0000000000000000E",
		"_ZN6rustls4conn6Reader4read17h0000000000000000E",
		"_ZN6quiche2h310Connection12send_request17h0000000000000000E",
	))
	coll := placeholderPrograms("uprobe_rustls_write", "uprobe_rustls_read", "uretprobe_rustls_read",
		"uprobe_quiche_rs_send_request")
	if n := len(AttachRustlsProbes(coll, pid)) + len(AttachQuicheRustProbes(coll, pid)); n != 0 {
		t.Errorf("attached %d links from placeholder programs", n)
	}
}

func TestUSDTProbesOpenABinaryWithProbeNotes(t *testing.T) {
	const pid = 4251
	sections := rustLikeSections("f")
	sections = append(sections, testSection{name: ".note.stapsdt", typ: shtNote, data: stapsdtNote(testTextVA, "app", "tick")})
	syntheticProc(t, pid, sections)
	orig := config.USDTEnabled
	config.USDTEnabled = true
	t.Cleanup(func() { config.USDTEnabled = orig })
	coll := placeholderPrograms("uprobe_usdt")
	coll.Maps = map[string]*ebpf.Map{"usdt_probes": {}}
	if n := len(AttachUSDTProbes(coll, pid)); n != 0 {
		t.Errorf("attached %d links from placeholder programs", n)
	}
}
