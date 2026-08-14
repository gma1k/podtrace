package quicinitial

import (
	"runtime"
	"testing"
)

func TestReassembleCrypto_HugeOffsetDoesNotAmplify(t *testing.T) {
	frame := []byte{0x06, 0x80, 0x0f, 0xff, 0xff, 0x01, 0xaa}

	if got := reassembleCrypto(frame); got != nil {
		t.Fatalf("huge-offset gap-only frame: got %x, want nil", got)
	}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	const iters = 2000
	for i := 0; i < iters; i++ {
		_ = reassembleCrypto(frame)
	}
	runtime.ReadMemStats(&after)
	if perCall := (after.TotalAlloc - before.TotalAlloc) / iters; perCall > 4096 {
		t.Fatalf("reassembleCrypto allocated %d bytes/call for a %d-byte frame; offset amplification regressed (was ~2MB)", perCall, len(frame))
	}
}

func TestReassembleCrypto_DropsChunkPastGap(t *testing.T) {
	crypto := func(off int, data []byte) []byte {
		return append([]byte{0x06, byte(off), byte(len(data))}, data...)
	}
	plain := append(crypto(0, []byte{0xaa}), crypto(10, []byte{0xbb})...)
	if got := reassembleCrypto(plain); string(got) != string([]byte{0xaa}) {
		t.Fatalf("chunk past a gap must be dropped: got %x, want aa", got)
	}
}

func TestReassembleCrypto_ContiguousAcrossFrames(t *testing.T) {
	crypto := func(off int, data []byte) []byte {
		return append([]byte{0x06, byte(off), byte(len(data))}, data...)
	}
	plain := append(crypto(0, []byte{0xaa, 0xbb}), crypto(2, []byte{0xcc})...)
	if got := reassembleCrypto(plain); string(got) != string([]byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("adjacent frames must join: got %x, want aabbcc", got)
	}
}

func TestReassembleCrypto_OutOfOrderContiguous(t *testing.T) {
	crypto := func(off int, data []byte) []byte {
		return append([]byte{0x06, byte(off), byte(len(data))}, data...)
	}
	plain := append(crypto(2, []byte{0xcc}), crypto(0, []byte{0xaa, 0xbb})...)
	if got := reassembleCrypto(plain); string(got) != string([]byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("frames given out of offset order must sort and join: got %x, want aabbcc", got)
	}
}
