package probes

import "testing"

func TestCopyCStringEmptyDst(t *testing.T) {
	copyCString([]byte{}, "anything")
	copyCString(nil, "anything")

	dst := make([]byte, 1)
	copyCString(dst, "x")
	if dst[0] != 0 {
		t.Errorf("single-byte buffer must hold only the NUL terminator, got %d", dst[0])
	}
}
