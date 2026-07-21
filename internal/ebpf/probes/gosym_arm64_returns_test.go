package probes

import (
	"encoding/binary"
	"testing"
)

func arm64RetBytes() []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, arm64RetInstruction)
	return b
}

func TestArm64ReturnPositions_SingleRetAfterNop(t *testing.T) {
	nop := []byte{0x1f, 0x20, 0x03, 0xd5}
	code := append(append([]byte{}, nop...), arm64RetBytes()...)
	got := arm64ReturnPositions(code)
	if len(got) != 1 || got[0] != 4 {
		t.Fatalf("positions = %v, want [4]", got)
	}
}

func TestArm64ReturnPositions_MultipleRets(t *testing.T) {
	nop := []byte{0x1f, 0x20, 0x03, 0xd5}
	ret := arm64RetBytes()
	code := append([]byte{}, ret...)
	code = append(code, nop...)
	code = append(code, ret...)
	got := arm64ReturnPositions(code)
	if len(got) != 2 || got[0] != 0 || got[1] != 8 {
		t.Fatalf("positions = %v, want [0 8]", got)
	}
}

func TestArm64ReturnPositions_NoRet(t *testing.T) {
	code := []byte{0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5}
	if got := arm64ReturnPositions(code); len(got) != 0 {
		t.Fatalf("positions = %v, want none", got)
	}
}

func TestArm64ReturnPositions_IgnoresTrailingPartialWord(t *testing.T) {
	code := append(arm64RetBytes(), 0x00, 0x11, 0x22)
	got := arm64ReturnPositions(code)
	if len(got) != 1 || got[0] != 0 {
		t.Fatalf("positions = %v, want [0] (partial trailing word ignored)", got)
	}
}

func TestArm64ReturnPositions_Empty(t *testing.T) {
	if got := arm64ReturnPositions(nil); got != nil {
		t.Fatalf("positions = %v, want nil for empty input", got)
	}
}
