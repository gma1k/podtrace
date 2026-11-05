package probes

import "testing"

const rustlsWriteSymbol = "_ZN6rustls4conn6Writer5write17h0000000000000000E"

func loadableRustSections(funcs ...string) []testSection {
	sections := rustLikeSections(funcs...)
	sections[0].load = true
	return sections
}

func TestRustlsWriteResolvesAFileOffsetBeforeAttaching(t *testing.T) {
	const pid = 4260
	syntheticProc(t, pid, loadableRustSections(rustlsWriteSymbol))
	coll := placeholderPrograms("uprobe_rustls_write", "uretprobe_rustls_write", "uprobe_rustls_read",
		"uretprobe_rustls_read")
	if n := len(AttachRustlsProbes(coll, pid)); n != 0 {
		t.Errorf("attached %d links from placeholder programs", n)
	}
}

func TestRustlsProbesNeedTheWriteReturnProgram(t *testing.T) {
	const pid = 4261
	syntheticProc(t, pid, loadableRustSections(rustlsWriteSymbol))
	coll := placeholderPrograms("uprobe_rustls_write", "uprobe_rustls_read", "uretprobe_rustls_read")
	if n := len(AttachRustlsProbes(coll, pid)); n != 0 {
		t.Errorf("attached %d links without the write return program", n)
	}
}
