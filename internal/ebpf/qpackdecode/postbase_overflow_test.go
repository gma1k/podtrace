package qpackdecode

import (
	"bytes"
	"math"
	"strings"
	"testing"
)

func TestPostBaseOverflows(t *testing.T) {
	cases := []struct {
		base, index uint64
		want        bool
	}{
		{1, 2, false},
		{0, math.MaxUint64, false},
		{math.MaxUint64, 0, false},
		{math.MaxUint64, 1, true},
		{1 << 63, 1 << 63, true},
		{1 << 63, (1 << 63) - 1, false},
	}
	for _, c := range cases {
		if got := postBaseOverflows(c.base, c.index); got != c.want {
			t.Errorf("postBaseOverflows(%d,%d)=%v want %v", c.base, c.index, got, c.want)
		}
	}
}

func overflowingPostBaseSection() []byte {
	maxTail := append(bytes.Repeat([]byte{0xff}, 8), 0x7f)
	section := append([]byte{0x00, 0x7f}, maxTail...)
	section = append(section, 0x1f)
	return append(section, maxTail...)
}

func TestPostBaseIndexOverflowFromTheWireIsRejected(t *testing.T) {
	d := NewDecoder(4096)
	if err := d.setCapacity(4096); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		if err := d.insert("x-entry", "v"); err != nil {
			t.Fatal(err)
		}
	}

	fields, err := d.DecodeFieldSection(overflowingPostBaseSection())
	if err == nil || !strings.Contains(err.Error(), "post-base index overflow") || len(fields) != 0 {
		t.Fatalf("fields %v err %v, want a post-base overflow error", fields, err)
	}

	fields, unresolved, err := d.DecodeFieldSectionBestEffort(overflowingPostBaseSection())
	if err != nil || unresolved != 1 || len(fields) != 0 {
		t.Fatalf("best effort: fields %v unresolved %d err %v", fields, unresolved, err)
	}
}
