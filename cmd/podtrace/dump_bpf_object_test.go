package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWritingTheBPFObjectRoundTripsVerbatim(t *testing.T) {
	obj := []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}
	path := filepath.Join(t.TempDir(), "podtrace.bpf.o")

	if err := writeBPFObject(path, obj); err != nil {
		t.Fatalf("writeBPFObject: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != string(obj) {
		t.Errorf("wrote %v, want %v.\n\nbpftool gen min_core_btf minimises against this "+
			"exact object; a truncated or altered copy yields a blob missing types "+
			"podtrace relocates against, which fails at load on the target node.", got, obj)
	}
}

func TestWritingABPFObjectThisBuildDoesNotHaveIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "podtrace.bpf.o")

	err := writeBPFObject(path, nil)
	if err == nil {
		t.Fatal("an empty object reported success; the user would take a zero-byte file " +
			"to bpftool and get a confusing failure there instead of here")
	}
	if !strings.Contains(err.Error(), "embed_bpf") {
		t.Errorf("error %q does not say why this build has no object", err)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("an empty file was created despite the error")
	}
}

func TestWritingToAnUnwritablePathReportsWhy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-dir", "podtrace.bpf.o")

	err := writeBPFObject(path, []byte{0x7f, 'E', 'L', 'F'})
	if err == nil {
		t.Fatal("writing into a directory that does not exist reported success")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q does not name the path it failed to write", err)
	}
}
