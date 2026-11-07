package h2decode

import "testing"

func TestTheAwaitedRecordCompletingAFullWindowIsNotAGap(t *testing.T) {
	d := New()
	d.maxPendingPerDir = 4
	enc := newBlockEncoder()
	split := enc.encode(reqFields("GET", "/split")...)
	half := len(split) / 2

	first := rec(12, DirEgress, 0, 1, split[:half])
	first.Flags = 0
	if evs := d.Ingest(first); len(evs) != 0 {
		t.Fatalf("first half of a header block emitted %d events", len(evs))
	}
	for seq := uint32(2); seq <= 5; seq++ {
		if evs := d.Ingest(rec(12, DirEgress, seq, 2*seq+1, enc.encode(reqFields("GET", "/later")...))); len(evs) != 0 {
			t.Fatalf("record %d decoded ahead of the missing one", seq)
		}
	}

	evs := d.Ingest(rec(12, DirEgress, 1, 1, split[half:]))
	if len(evs) != 5 {
		t.Fatalf("got %d events once the awaited record arrived, want 5", len(evs))
	}
	if evs[0].Target != "GET /split" {
		t.Errorf("first target = %q; the block split across the awaited record was dropped", evs[0].Target)
	}
	for _, ev := range evs[1:] {
		if ev.Target != "GET /later" {
			t.Errorf("target = %q, want GET /later", ev.Target)
		}
	}
	if s := d.Stats(); s.GapsSkipped != 0 || s.PartialBlocks != 0 {
		t.Errorf("gaps=%d partial=%d, nothing was lost", s.GapsSkipped, s.PartialBlocks)
	}
}
