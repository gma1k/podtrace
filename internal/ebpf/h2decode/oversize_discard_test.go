package h2decode

import (
	"bytes"
	"testing"
	"time"
)

func TestDrain_OversizeDropDiscardsRestOfBlock(t *testing.T) {
	d := New()
	d.maxAssembly = 64

	frag1 := rec(1, 0, 0, 1, bytes.Repeat([]byte{0x00}, 200))
	frag1.Flags = 0
	frag1.FragLen = uint16(len(frag1.Frag))
	if evs := d.Ingest(frag1); len(evs) != 0 {
		t.Fatalf("oversize partial fragment must emit nothing, got %d", len(evs))
	}

	tail := newBlockEncoder().encode(reqFields("GET", "/injected")...)
	if evs := d.Ingest(rec(1, 0, 1, 1, tail)); len(evs) != 0 {
		t.Fatalf("a CONTINUATION tail after an oversize drop must be discarded, not decoded as a fresh block; got %d fabricated events: %+v", len(evs), evs)
	}

	fresh := newBlockEncoder().encode(reqFields("GET", "/real")...)
	if evs := d.Ingest(rec(1, 0, 2, 3, fresh)); len(evs) != 1 {
		t.Fatalf("a genuine fresh block after recovery must still decode (discarding must clear), got %d", len(evs))
	}
}

func TestSkipGap_MidBlockDiscardsRestOfBlock(t *testing.T) {
	d := New()
	base := time.Unix(1000, 0)
	now := base
	d.nowFn = func() time.Time { return now }

	partial := rec(1, 0, 0, 1, newBlockEncoder().encode(reqFields("GET", "/partial")...))
	partial.Flags = 0
	partial.FragLen = uint16(len(partial.Frag))
	if evs := d.Ingest(partial); len(evs) != 0 {
		t.Fatalf("mid-block partial must emit nothing, got %d", len(evs))
	}

	// seq 1 is lost; seq 2 (a decodable block) stalls behind the gap.
	if evs := d.Ingest(rec(1, 0, 2, 1, newBlockEncoder().encode(reqFields("GET", "/injected")...))); len(evs) != 0 {
		t.Fatalf("seq2 must stall behind the seq1 gap, got %d", len(evs))
	}

	now = base.Add(d.gapTimeout + time.Second)
	if evs := d.Sweep(); len(evs) != 0 {
		t.Fatalf("after a mid-block gap skip, the tail must be discarded, not decoded as a fresh block; got %d fabricated events: %+v", len(evs), evs)
	}
}
