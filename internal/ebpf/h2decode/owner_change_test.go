package h2decode

import (
	"strings"
	"testing"
)

func ownedRec(conn uint64, cgroup uint64, seq, stream uint32, block []byte) *RawRecord {
	r := rec(conn, DirEgress, seq, stream, block)
	r.CgroupID = cgroup
	return r
}

func TestAReusedSocketFromAnotherCgroupDoesNotDecodeWithTheOldHPACKTable(t *testing.T) {
	d := New()
	enc := newBlockEncoder()
	secret := hf("authorization", "Bearer tenant-a-token")
	first := enc.encode(reqFields("GET", "/tenant-a/private", secret)...)
	if ev := singleEvent(t, d.Ingest(ownedRec(0x61, 100, 0, 1, first))); ev.Target != "GET /tenant-a/private" {
		t.Fatalf("first owner target = %q", ev.Target)
	}

	reused := enc.encode(reqFields("GET", "/tenant-a/private", secret)...)
	for _, ev := range d.Ingest(ownedRec(0x61, 200, 1, 3, reused)) {
		if strings.Contains(ev.Target, "tenant-a") || strings.Contains(ev.Details, "tenant-a") {
			t.Fatalf("new owner decoded the old owner's dynamic table: target=%q details=%q", ev.Target, ev.Details)
		}
	}
	if s := d.Stats(); s.OwnerChanges != 1 {
		t.Fatalf("owner changes = %d, want 1", s.OwnerChanges)
	}
}

func TestTheSameCgroupKeepsItsHPACKTable(t *testing.T) {
	d := New()
	enc := newBlockEncoder()
	d.Ingest(ownedRec(0x62, 100, 0, 1, enc.encode(reqFields("GET", "/same")...)))
	ev := singleEvent(t, d.Ingest(ownedRec(0x62, 100, 1, 3, enc.encode(reqFields("GET", "/same")...))))
	if ev.Target != "GET /same" {
		t.Fatalf("target = %q, want the indexed path resolved", ev.Target)
	}
	if s := d.Stats(); s.OwnerChanges != 0 {
		t.Fatalf("owner changes = %d, want 0", s.OwnerChanges)
	}
}

func TestRecordsWithoutACgroupNeverResetTheConnection(t *testing.T) {
	d := New()
	enc := newBlockEncoder()
	d.Ingest(ownedRec(0x63, 100, 0, 1, enc.encode(reqFields("GET", "/kept")...)))
	ev := singleEvent(t, d.Ingest(ownedRec(0x63, 0, 1, 3, enc.encode(reqFields("GET", "/kept")...))))
	if ev.Target != "GET /kept" {
		t.Fatalf("target = %q, want the indexed path resolved", ev.Target)
	}
	if s := d.Stats(); s.OwnerChanges != 0 {
		t.Fatalf("owner changes = %d, want 0", s.OwnerChanges)
	}
}

func TestAnOwnerChangeReleasesTheOldOwnersHeldResponses(t *testing.T) {
	d := New()
	enc := newBlockEncoder()
	d.Ingest(ownedRec(0x64, 100, 0, 1, enc.encode(reqFields("GET", "/a")...)))
	before := d.Stats().Streams
	d.Ingest(ownedRec(0x64, 200, 1, 3, newBlockEncoder().encode(reqFields("GET", "/b")...)))
	if s := d.Stats(); s.OwnerChanges != 1 || s.Streams > before {
		t.Fatalf("stats after owner change = %+v, streams before = %d", s, before)
	}
}
