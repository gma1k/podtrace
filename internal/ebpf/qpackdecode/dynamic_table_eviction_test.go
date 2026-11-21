package qpackdecode

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func newTableDecoder(t *testing.T, capacity uint64) *Decoder {
	t.Helper()
	d := NewDecoder(capacity)
	if err := d.setCapacity(capacity); err != nil {
		t.Fatal(err)
	}
	return d
}

func assertEvictedSlotsZeroed(t *testing.T, d *Decoder) {
	t.Helper()
	for i, e := range d.entries[:d.head] {
		if e != (tableEntry{}) {
			t.Fatalf("evicted slot %d still holds %q=%q", i, e.name, e.value)
		}
	}
}

func assertLiveEntries(t *testing.T, d *Decoder) {
	t.Helper()
	for abs := d.evicted; abs < d.InsertCount(); abs++ {
		e, err := d.absoluteEntry(abs)
		if err != nil {
			t.Fatalf("entry %d: %v", abs, err)
		}
		if want := fmt.Sprintf("v%d", abs); e.value != want {
			t.Fatalf("entry %d = %q, want %q", abs, e.value, want)
		}
	}
}

func TestEvictedEntriesReleaseTheirStrings(t *testing.T) {
	d := newTableDecoder(t, 4096)
	for i := 0; i < 500; i++ {
		if err := d.insert("name", fmt.Sprintf("v%d", i)+strings.Repeat("x", i%200)); err != nil {
			t.Fatal(err)
		}
		assertEvictedSlotsZeroed(t, d)
	}
	if d.evicted == 0 {
		t.Fatal("test never evicted")
	}
}

func TestEntriesResolveAcrossCompaction(t *testing.T) {
	d := newTableDecoder(t, 1024)
	for i := 0; i < 2000; i++ {
		value := fmt.Sprintf("v%d", d.InsertCount())
		if err := d.insert(strings.Repeat("n", (i%7)*40), value); err != nil {
			t.Fatal(err)
		}
		assertLiveEntries(t, d)
		latest, err := d.relativeEntry(0)
		if err != nil || latest.value != value {
			t.Fatalf("relative 0 = %+v %v, want %q", latest, err, value)
		}
	}
	if _, err := d.absoluteEntry(d.evicted - 1); err == nil {
		t.Fatal("evicted entry still resolvable")
	}
}

func TestLargeEvictionsShrinkTheBackingArray(t *testing.T) {
	d := newTableDecoder(t, maxTableCapacity)
	for i := 0; i < 2048; i++ {
		if err := d.insert("", ""); err != nil {
			t.Fatal(err)
		}
	}
	grown := cap(d.entries)
	big := strings.Repeat("v", maxFieldLength)
	for i := 0; i < 400; i++ {
		if err := d.insert(strings.Repeat("n", maxFieldLength), big); err != nil {
			t.Fatal(err)
		}
		assertEvictedSlotsZeroed(t, d)
	}
	live := len(d.entries) - d.head
	if cap(d.entries) >= grown || cap(d.entries) > 4*live+16 {
		t.Fatalf("backing array cap %d for %d live entries (was %d)", cap(d.entries), live, grown)
	}
}

func TestRetainedBytesChargesTheBackingArray(t *testing.T) {
	d := newTableDecoder(t, maxTableCapacity)
	for i := 0; i < 2048; i++ {
		if err := d.insert("", ""); err != nil {
			t.Fatal(err)
		}
	}
	want := int(d.size) + cap(d.entries)*tableSlotBytes
	if got := d.RetainedBytes(); got != want || got <= int(d.size) {
		t.Fatalf("RetainedBytes = %d, want %d", got, want)
	}
}

func TestEvictingTheWholeTableEmptiesIt(t *testing.T) {
	d := newTableDecoder(t, 4096)
	for i := 0; i < 100; i++ {
		if err := d.insert("k", fmt.Sprintf("v%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.setCapacity(0); err != nil {
		t.Fatal(err)
	}
	if len(d.entries) != 0 || d.head != 0 || d.size != 0 || d.InsertCount() != 100 {
		t.Fatalf("entries %d head %d size %d inserts %d", len(d.entries), d.head, d.size, d.InsertCount())
	}
}

func TestFieldSectionAtTheFieldLineCapDecodes(t *testing.T) {
	d := NewDecoder(0)
	section := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0xd1}, maxFieldsPerSection)...)
	fields, err := d.DecodeFieldSection(section)
	if err != nil || len(fields) != maxFieldsPerSection {
		t.Fatalf("got %d fields, err %v", len(fields), err)
	}
}

func TestFieldSectionOverTheFieldLineCapIsRejected(t *testing.T) {
	d := NewDecoder(0)
	section := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0xd1}, 4080)...)
	if _, err := d.DecodeFieldSection(section); !errors.Is(err, errTooManyFields) {
		t.Fatalf("err = %v, want errTooManyFields", err)
	}
}

func TestBestEffortCountsUnresolvedLinesTowardTheCap(t *testing.T) {
	d := NewDecoder(0)
	section := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x80}, maxFieldsPerSection+1)...)
	if _, _, err := d.DecodeFieldSectionBestEffort(section); !errors.Is(err, errTooManyFields) {
		t.Fatalf("err = %v, want errTooManyFields", err)
	}
	_, unresolved, err := d.DecodeFieldSectionBestEffort(section[:len(section)-1])
	if err != nil || unresolved != maxFieldsPerSection {
		t.Fatalf("unresolved %d err %v", unresolved, err)
	}
}
