package h2decode

import (
	"errors"
	"testing"
)

func TestDecodeBlockTooManyFields(t *testing.T) {

	block := make([]byte, maxFieldsPerBlock+1)
	for i := range block {
		block[i] = 0x82
	}
	d := &lateJoinDecoder{}
	if _, _, err := d.decodeBlock(block); !errors.Is(err, errHPACKTooManyFields) {
		t.Fatalf("err = %v, want errHPACKTooManyFields", err)
	}
}

func TestDecodeBlockSizeUpdateTruncated(t *testing.T) {

	d := &lateJoinDecoder{}
	if _, _, err := d.decodeBlock([]byte{0x3f}); !errors.Is(err, errHPACKTruncated) {
		t.Fatalf("err = %v, want errHPACKTruncated", err)
	}
}

func TestDecodeBlockSizeUpdateAccepted(t *testing.T) {

	d := &lateJoinDecoder{}
	fields, complete, err := d.decodeBlock([]byte{0x20, 0x82})
	if err != nil || !complete {
		t.Fatalf("size update block: complete=%v err=%v", complete, err)
	}
	if len(fields) != 1 || fields[0].Name != ":method" || fields[0].Value != "GET" {
		t.Fatalf("fields = %v", fields)
	}
}

func TestReadLiteralNameIndexOutOfRange(t *testing.T) {

	block := []byte{0x7f, 0xe9, 0x45}
	d := &lateJoinDecoder{}
	if _, _, err := d.decodeBlock(block); !errors.Is(err, errHPACKIndexRange) {
		t.Fatalf("err = %v, want errHPACKIndexRange", err)
	}
}

func TestReadLiteralTruncatedNameString(t *testing.T) {

	block := []byte{0x40, 0x05, 'a'}
	d := &lateJoinDecoder{}
	if _, _, err := d.decodeBlock(block); !errors.Is(err, errHPACKTruncated) {
		t.Fatalf("err = %v, want errHPACKTruncated", err)
	}
}

func TestLiteralWithoutIndexingUnresolvedName(t *testing.T) {

	block := []byte{0x0f, 0x2f, 0x01, 'x'}
	d := &lateJoinDecoder{}
	fields, complete, err := d.decodeBlock(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if complete {
		t.Fatal("block referencing pre-attach name must be partial")
	}
	if len(fields) != 0 {
		t.Fatalf("unresolved literal produced fields: %v", fields)
	}
}

func TestReadLiteralNameIntegerTruncated(t *testing.T) {

	d := &lateJoinDecoder{}
	if _, _, err := d.decodeBlock([]byte{0x7f}); !errors.Is(err, errHPACKTruncated) {
		t.Fatalf("err = %v, want errHPACKTruncated", err)
	}
}

func TestReadStringEmptyBuffer(t *testing.T) {

	d := &lateJoinDecoder{}
	if _, _, err := d.decodeBlock([]byte{0x41}); !errors.Is(err, errHPACKTruncated) {
		t.Fatalf("err = %v, want errHPACKTruncated", err)
	}
}

func TestReadStringLengthTruncated(t *testing.T) {

	d := &lateJoinDecoder{}
	if _, _, err := d.decodeBlock([]byte{0x41, 0xff}); !errors.Is(err, errHPACKTruncated) {
		t.Fatalf("err = %v, want errHPACKTruncated", err)
	}
}

func TestReadStringHuffmanError(t *testing.T) {

	block := []byte{0x00, 0x01, 'x', 0x84, 0xff, 0xff, 0xff, 0xff}
	d := &lateJoinDecoder{}
	if _, _, err := d.decodeBlock(block); err == nil {
		t.Fatal("invalid Huffman value accepted")
	}
}
