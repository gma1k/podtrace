package h2decode

import "testing"

func TestEmptyFragmentRecordsStillChargeTheBudget(t *testing.T) {
	d := New()
	cost := 0
	for seq := uint32(1); seq <= 100; seq++ {
		r := rec(0x70, DirEgress, seq, 1, nil)
		r.Flags = 0
		r.PeerSrcIP, r.PeerDstIP = "10.0.0.1", "10.0.0.2"
		cost += r.pendingCost()
		d.Ingest(r)
	}
	if s := d.Stats(); s.RetainedBytes != cost || cost < 100*pendingRecordOverhead {
		t.Fatalf("retained %d, want %d", s.RetainedBytes, cost)
	}
	d.Evict(0x70)
	if s := d.Stats(); s.RetainedBytes != 0 {
		t.Fatalf("retained bytes drifted to %d", s.RetainedBytes)
	}
}

func TestEmptyFragmentFloodIsShed(t *testing.T) {
	d := New()
	d.maxRetainedBytes = 50 * pendingRecordOverhead
	for conn := uint64(1); conn <= 8; conn++ {
		for seq := uint32(1); seq <= 20; seq++ {
			r := rec(conn, DirEgress, seq, 1, nil)
			r.Flags = 0
			d.Ingest(r)
		}
	}
	s := d.Stats()
	if s.BudgetSheds == 0 || s.RetainedBytes > d.maxRetainedBytes {
		t.Fatalf("sheds=%d retained=%d budget=%d", s.BudgetSheds, s.RetainedBytes, d.maxRetainedBytes)
	}
}

func TestPendingCostCountsRecordFragmentAndPeers(t *testing.T) {
	r := &RawRecord{Frag: make([]byte, 10, 64), PeerSrcIP: "fd00::1", PeerDstIP: "fd00::2"}
	if got, want := r.pendingCost(), pendingRecordOverhead+64+7+7; got != want {
		t.Fatalf("pendingCost = %d, want %d", got, want)
	}
}
