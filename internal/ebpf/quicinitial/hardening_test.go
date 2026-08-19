package quicinitial

import (
	"strings"
	"testing"
)

func TestDecryptInitial_ScidOutOfRange(t *testing.T) {
	b := []byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x02, 0xaa, 0xbb, 0x05}
	_, _, err := decryptInitial(b)
	if err == nil || !strings.Contains(err.Error(), "scid") {
		t.Fatalf("a SCID length past the buffer must be rejected explicitly, got err=%v", err)
	}
}

func TestBlock2_BadKeyReturnsError(t *testing.T) {
	if _, err := block2(make([]byte, 15)); err == nil {
		t.Fatal("block2 must return an error for an invalid key length instead of a nil cipher")
	}
	b, err := block2(make([]byte, 16))
	if err != nil || b == nil {
		t.Fatalf("block2 with a valid 16-byte key: block=%v err=%v", b, err)
	}
}
