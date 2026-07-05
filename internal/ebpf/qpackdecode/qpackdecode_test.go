package qpackdecode

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"golang.org/x/net/http2/hpack"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func expectFields(t *testing.T, got []HeaderField, want ...HeaderField) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d fields %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("field %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestRFC9204AppendixB replays the worked example from RFC 9204 Appendix B
// end to end: field sections B.1, B.2 and B.4 plus the encoder stream
// instructions of B.2, B.3, B.4 and B.5.
func TestRFC9204AppendixB(t *testing.T) {
	d := NewDecoder(0)

	fields, err := d.DecodeFieldSection(mustHex(t, "0000 510b 2f69 6e64 6578 2e68 746d 6c"))
	if err != nil {
		t.Fatalf("B.1: %v", err)
	}
	expectFields(t, fields, HeaderField{Name: ":path", Value: "/index.html"})

	err = d.ParseEncoderStream(mustHex(t,
		"3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d c10c 2f73 616d 706c 652f 7061 7468"))
	if err != nil {
		t.Fatalf("B.2 encoder stream: %v", err)
	}
	if d.InsertCount() != 2 {
		t.Fatalf("insert count = %d, want 2", d.InsertCount())
	}
	if d.size != 106 {
		t.Fatalf("table size = %d, want 106", d.size)
	}

	fields, err = d.DecodeFieldSection(mustHex(t, "0381 10 11"))
	if err != nil {
		t.Fatalf("B.2 section: %v", err)
	}
	expectFields(t, fields,
		HeaderField{Name: ":authority", Value: "www.example.com"},
		HeaderField{Name: ":path", Value: "/sample/path"})

	err = d.ParseEncoderStream(mustHex(t,
		"4a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65"))
	if err != nil {
		t.Fatalf("B.3 encoder stream: %v", err)
	}
	if d.InsertCount() != 3 || d.size != 160 {
		t.Fatalf("after B.3: insert count %d size %d, want 3/160", d.InsertCount(), d.size)
	}

	if err := d.ParseEncoderStream(mustHex(t, "02")); err != nil {
		t.Fatalf("B.4 encoder stream: %v", err)
	}
	if d.InsertCount() != 4 || d.size != 217 {
		t.Fatalf("after B.4: insert count %d size %d, want 4/217", d.InsertCount(), d.size)
	}

	fields, err = d.DecodeFieldSection(mustHex(t, "0500 80 c1 81"))
	if err != nil {
		t.Fatalf("B.4 section: %v", err)
	}
	expectFields(t, fields,
		HeaderField{Name: ":authority", Value: "www.example.com"},
		HeaderField{Name: ":path", Value: "/"},
		HeaderField{Name: "custom-key", Value: "custom-value"})

	err = d.ParseEncoderStream(mustHex(t, "81 0d63 7573 746f 6d2d 7661 6c75 6532"))
	if err != nil {
		t.Fatalf("B.5 encoder stream: %v", err)
	}
	if d.InsertCount() != 5 || d.size != 215 || d.evicted != 1 {
		t.Fatalf("after B.5: insert count %d size %d evicted %d, want 5/215/1",
			d.InsertCount(), d.size, d.evicted)
	}

	if _, err := d.DecodeFieldSection(mustHex(t, "0600 84")); err == nil {
		t.Fatal("reference to evicted entry did not fail")
	}
}

func TestBlockedSection(t *testing.T) {
	d := NewDecoder(220)
	section := mustHex(t, "0381 10 11")

	_, err := d.DecodeFieldSection(section)
	var blocked *BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("got %v, want BlockedError", err)
	}
	if blocked.RequiredInsertCount != 2 || blocked.InsertCount != 0 {
		t.Fatalf("blocked = %+v, want required 2 have 0", blocked)
	}

	err = d.ParseEncoderStream(mustHex(t,
		"3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d c10c 2f73 616d 706c 652f 7061 7468"))
	if err != nil {
		t.Fatalf("encoder stream: %v", err)
	}
	fields, err := d.DecodeFieldSection(section)
	if err != nil {
		t.Fatalf("after unblocking: %v", err)
	}
	expectFields(t, fields,
		HeaderField{Name: ":authority", Value: "www.example.com"},
		HeaderField{Name: ":path", Value: "/sample/path"})
}

// TestEncoderStreamByteAtATime feeds the B.2+B.3 encoder stream one byte at
// a time; instructions split across chunks must decode identically.
func TestEncoderStreamByteAtATime(t *testing.T) {
	d := NewDecoder(0)
	stream := mustHex(t,
		"3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d c10c 2f73 616d 706c 652f 7061 7468"+
			"4a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65")
	for _, b := range stream {
		if err := d.ParseEncoderStream([]byte{b}); err != nil {
			t.Fatalf("byte-at-a-time: %v", err)
		}
	}
	if d.InsertCount() != 3 || d.size != 160 {
		t.Fatalf("insert count %d size %d, want 3/160", d.InsertCount(), d.size)
	}
}

func TestHuffmanLiterals(t *testing.T) {
	d := NewDecoder(0)

	name := hpack.AppendHuffmanString(nil, "x-hdr")
	value := hpack.AppendHuffmanString(nil, "hello world")
	if len(name) > 7 || len(value) > 127 {
		t.Fatal("test strings too long for single-byte length prefixes")
	}
	section := []byte{0x00, 0x00, 0x20 | 0x08 | byte(len(name))}
	section = append(section, name...)
	section = append(section, 0x80|byte(len(value)))
	section = append(section, value...)

	fields, err := d.DecodeFieldSection(section)
	if err != nil {
		t.Fatalf("huffman literals: %v", err)
	}
	expectFields(t, fields, HeaderField{Name: "x-hdr", Value: "hello world"})
}

// TestBestEffortLateJoin simulates attaching mid-connection: the encoder
// stream prefix was never observed, so dynamic references are unresolvable
// but static and literal fields still decode.
func TestBestEffortLateJoin(t *testing.T) {
	d := NewDecoder(220)

	section := mustHex(t, "0381 10 d1 51 02 2f 78")

	if _, err := d.DecodeFieldSection(section); err == nil {
		t.Fatal("strict decode of blocked section succeeded")
	}
	fields, unresolved, err := d.DecodeFieldSectionBestEffort(section)
	if err != nil {
		t.Fatalf("best effort: %v", err)
	}
	if unresolved != 1 {
		t.Fatalf("unresolved = %d, want 1", unresolved)
	}
	expectFields(t, fields,
		HeaderField{Name: ":method", Value: "GET"},
		HeaderField{Name: ":path", Value: "/x"})
}

// TestRequiredInsertCountWraparound exercises the modulo reconstruction of
// RFC 9204 §4.5.1.1 past the first wrap of the encoded space.
func TestRequiredInsertCountWraparound(t *testing.T) {
	d := NewDecoder(220) // maxEntries 6, full range 12

	if err := d.ParseEncoderStream(mustHex(t, "3fbd01")); err != nil {
		t.Fatalf("set capacity: %v", err)
	}
	for i := 0; i < 25; i++ {
		name := []byte{'k', byte('0' + i/10), byte('0' + i%10)}
		instruction := []byte{0x40 | byte(len(name))}
		instruction = append(instruction, name...)
		instruction = append(instruction, 0x01, 'v')
		if err := d.ParseEncoderStream(instruction); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	if d.InsertCount() != 25 {
		t.Fatalf("insert count = %d, want 25", d.InsertCount())
	}

	fields, err := d.DecodeFieldSection(mustHex(t, "0200 80"))
	if err != nil {
		t.Fatalf("wraparound section: %v", err)
	}
	expectFields(t, fields, HeaderField{Name: "k24", Value: "v"})
}

func TestMalformedInput(t *testing.T) {
	cases := map[string]string{
		"empty section":              "",
		"prefix only":                "00",
		"truncated literal value":    "0000 510b 2f69",
		"static index out of range":  "0000 ff2c",
		"truncated prefixed integer": "0000 ff",
		"truncated name reference":   "0000 5f",
	}
	for name, in := range cases {
		d := NewDecoder(0)
		if _, err := d.DecodeFieldSection(mustHex(t, in)); err == nil {
			t.Errorf("%s: decode succeeded, want error", name)
		}
	}

	d := NewDecoder(0)
	if err := d.ParseEncoderStream(mustHex(t, "20")); err != nil {
		t.Fatalf("set capacity 0: %v", err)
	}
	err := d.ParseEncoderStream(mustHex(t, "4a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65"))
	if err == nil {
		t.Fatal("insert into zero-capacity table succeeded")
	}
}

func TestStaticTableSize(t *testing.T) {
	if len(staticTable) != 99 {
		t.Fatalf("static table has %d entries, want 99", len(staticTable))
	}
	checks := map[int]HeaderField{
		0:  {Name: ":authority"},
		1:  {Name: ":path", Value: "/"},
		17: {Name: ":method", Value: "GET"},
		25: {Name: ":status", Value: "200"},
		98: {Name: "x-frame-options", Value: "sameorigin"},
	}
	for i, want := range checks {
		if staticTable[i] != want {
			t.Errorf("staticTable[%d] = %+v, want %+v", i, staticTable[i], want)
		}
	}
}
