package probes

import (
	"debug/elf"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/safeelf"
)

func TestFindSymbolsContaining_OverCapSymtabReturnsNil(t *testing.T) {
	f := &elf.File{Sections: []*elf.Section{
		{SectionHeader: elf.SectionHeader{Name: ".symtab", Size: safeelf.MaxSectionSize + 1}},
	}}
	if got := findSymbolsContaining(f, 4, "anything"); got != nil {
		t.Errorf("an over-cap .symtab must be refused before parsing, got %v", got)
	}
}

func TestAttachQuicheRustProbes_MalformedExeNoPanic(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("quiche resolver only runs on amd64")
	}
	orig := config.ProcBasePath
	defer config.SetProcBasePath(orig)

	dir := t.TempDir()
	config.SetProcBasePath(dir)
	pidDir := filepath.Join(dir, "4242")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "exe"), []byte("this is not an ELF binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	coll := &ebpf.Collection{Programs: map[string]*ebpf.Program{
		"uprobe_quiche_rs_send_request": {},
	}}
	if got := AttachQuicheRustProbes(coll, 4242); got != nil {
		t.Errorf("a non-ELF exe must yield no links (and never panic), got %v", got)
	}
}
