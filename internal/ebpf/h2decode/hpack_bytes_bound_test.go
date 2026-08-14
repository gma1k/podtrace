package h2decode

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/net/http2/hpack"
)

func appendHPACKInteger(dst []byte, i, prefixBits int) []byte {
	max := (1 << uint(prefixBits)) - 1
	if i < max {
		return append(dst, byte(i))
	}
	dst = append(dst, byte(max))
	i -= max
	for i >= 128 {
		dst = append(dst, byte(i%128+128))
		i /= 128
	}
	return append(dst, byte(i))
}

func hpackStringLiteral(huffman bool, payload []byte) []byte {
	buf := appendHPACKInteger(nil, len(payload), 7)
	if huffman {
		buf[0] |= 0x80
	}
	return append(buf, payload...)
}

func TestReadString_RawFieldExceedingLimitRejected(t *testing.T) {
	buf := hpackStringLiteral(false, make([]byte, maxFieldLength+1))
	if _, _, err := readString(buf); !errors.Is(err, errHPACKFieldTooLong) {
		t.Fatalf("readString err = %v, want errHPACKFieldTooLong", err)
	}
}

func TestReadString_HuffmanDecodedExceedingLimitRejected(t *testing.T) {
	s := strings.Repeat("0", maxFieldLength+1)
	huff := hpack.AppendHuffmanString(nil, s)
	if len(huff) > maxFieldLength {
		t.Fatalf("huffman payload %d bytes is itself over the raw cap; test premise broken", len(huff))
	}
	buf := hpackStringLiteral(true, huff)
	if _, _, err := readString(buf); !errors.Is(err, errHPACKFieldTooLong) {
		t.Fatalf("readString err = %v, want errHPACKFieldTooLong (decoded len %d)", err, len(s))
	}
}

func TestReadString_AtLimitAccepted(t *testing.T) {
	payload := []byte(strings.Repeat("a", maxFieldLength))
	buf := hpackStringLiteral(false, payload)
	s, _, err := readString(buf)
	if err != nil {
		t.Fatalf("field at the limit must decode: %v", err)
	}
	if len(s) != maxFieldLength {
		t.Fatalf("decoded len = %d, want %d", len(s), maxFieldLength)
	}
}

func TestInsert_WindowBoundedByBytes(t *testing.T) {
	d := &lateJoinDecoder{}
	big := strings.Repeat("x", maxFieldLength)
	for i := 0; i < 200; i++ {
		d.insert(tableEntry{field: hpack.HeaderField{Name: "n", Value: big}})
	}

	if d.trackedBytes > maxTrackedBytes {
		t.Fatalf("trackedBytes = %d exceeds cap %d", d.trackedBytes, maxTrackedBytes)
	}
	if len(d.inserts) >= 200 {
		t.Fatalf("window not byte-bounded: %d of 200 large entries retained", len(d.inserts))
	}

	sum := 0
	for _, e := range d.inserts {
		sum += entrySize(e)
	}
	if sum != d.trackedBytes {
		t.Fatalf("trackedBytes accounting drift: tracked %d vs actual %d", d.trackedBytes, sum)
	}
}

func TestInsert_ResetEpochClearsByteCount(t *testing.T) {
	d := &lateJoinDecoder{}
	d.insert(tableEntry{field: hpack.HeaderField{Name: "n", Value: "v"}})
	if d.trackedBytes == 0 {
		t.Fatal("trackedBytes should be non-zero after insert")
	}
	d.resetEpoch()
	if d.trackedBytes != 0 || len(d.inserts) != 0 {
		t.Fatalf("resetEpoch must clear window: bytes=%d len=%d", d.trackedBytes, len(d.inserts))
	}
}
