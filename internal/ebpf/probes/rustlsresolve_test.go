package probes

import "testing"

func TestRustlsSymbolPatterns(t *testing.T) {
	const writeSym = "_ZN67_$LT$rustls..conn..connection..Writer$u20$as$u20$std..io..Write$GT$5write17h047145b15f069e6fE"
	const readSym = "_ZN66_$LT$rustls..conn..connection..Reader$u20$as$u20$std..io..Read$GT$4read17h879fa3fd0b5fb779E"
	const flushSym = "_ZN67_$LT$rustls..conn..connection..Writer$u20$as$u20$std..io..Write$GT$5flush17h14ac3a26f8f7ff71E"
	const writeAllSym = "_ZN67_$LT$rustls..conn..connection..Writer$u20$as$u20$std..io..Write$GT$9write_all17habcdef0123456789E"

	if !nameContainsAll(writeSym, rustlsWriteSymbolPattern...) {
		t.Errorf("write symbol should match the write pattern: %s", writeSym)
	}
	if !nameContainsAll(readSym, rustlsReadSymbolPattern...) {
		t.Errorf("read symbol should match the read pattern: %s", readSym)
	}
	if nameContainsAll(flushSym, rustlsWriteSymbolPattern...) {
		t.Error("flush symbol must not match the write pattern")
	}
	if nameContainsAll(writeAllSym, rustlsWriteSymbolPattern...) {
		t.Error("write_all symbol must not match the write pattern (anchor is $GT$5write)")
	}
	if nameContainsAll(readSym, rustlsWriteSymbolPattern...) {
		t.Error("read symbol must not match the write pattern")
	}
	const bufWriter = "_ZN3std2io8buffered9bufwriter18BufWriter$LT$W$GT$5write17hdeadbeefdeadbeefE"
	if nameContainsAll(bufWriter, rustlsWriteSymbolPattern...) {
		t.Error("non-rustls writer must not match the write pattern")
	}
}