package probes

import "testing"

// TestX86ReturnPositions_Clean finds RET at the right offset in valid code.
func TestX86ReturnPositions_Clean(t *testing.T) {
	// 0x90 NOP, 0xc3 RET
	got := x86ReturnPositions([]byte{0x90, 0xc3})
	if len(got) != 1 || got[0] != 1 {
		t.Fatalf("positions = %v, want [1]", got)
	}
}

// TestX86ReturnPositions_StopsOnDesync guards ebpf M1: after an undecodable
// byte (0x06 = PUSH ES, invalid in 64-bit mode) the scan must stop rather than
// resync mid-instruction and report a spurious RET, which would plant a
// uretprobe mid-instruction and corrupt the traced process.
func TestX86ReturnPositions_StopsOnDesync(t *testing.T) {
	got := x86ReturnPositions([]byte{0x06, 0x90, 0xc3})
	if len(got) != 0 {
		t.Fatalf("expected no positions after a decode failure, got %v", got)
	}
}
