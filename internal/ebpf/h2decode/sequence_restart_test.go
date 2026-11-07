package h2decode

import (
	"fmt"
	"testing"
	"time"
)

func ingestRequests(d *Decoder, enc *blockEncoder, conn uint64, firstSeq uint32, count int, prefix string) int {
	events := 0
	for i := 0; i < count; i++ {
		seq := firstSeq + uint32(i)
		block := enc.encode(reqFields("GET", fmt.Sprintf("/%s/%d", prefix, i))...)
		events += len(d.Ingest(rec(conn, DirEgress, seq, 2*seq+1, block)))
	}
	return events
}

func TestSequenceRestartStartsANewConnection(t *testing.T) {
	d := New()
	if got := ingestRequests(d, newBlockEncoder(), 0x51, 0, 1000, "old"); got != 1000 {
		t.Fatalf("first connection events = %d, want 1000", got)
	}

	enc := newBlockEncoder()
	var last string
	got := 0
	for i := 0; i < 900; i++ {
		block := enc.encode(reqFields("GET", fmt.Sprintf("/new/%d", i))...)
		for _, ev := range d.Ingest(rec(0x51, DirEgress, uint32(i), uint32(2*i+1), block)) {
			got++
			last = ev.Target
		}
	}
	if got != 900 {
		t.Fatalf("events after sequence restart = %d, want 900", got)
	}
	if last != "GET /new/899" {
		t.Fatalf("last target = %q, want the new connection's own path", last)
	}
	if s := d.Stats(); s.SequenceRestarts != 1 {
		t.Fatalf("sequence restarts = %d, want 1", s.SequenceRestarts)
	}
}

func TestRecordFromSkippedGapIsLateNotRestart(t *testing.T) {
	d := New()
	d.maxPendingPerDir = 2
	enc := newBlockEncoder()
	d.Ingest(rec(0x52, DirEgress, 0, 1, enc.encode(reqFields("GET", "/a")...)))
	for seq := uint32(2); seq <= 4; seq++ {
		d.Ingest(rec(0x52, DirEgress, seq, 2*seq+1, enc.encode(reqFields("GET", "/b")...)))
	}
	if evs := d.Ingest(rec(0x52, DirEgress, 1, 3, enc.encode(reqFields("GET", "/late")...))); len(evs) != 0 {
		t.Fatalf("late record decoded: %d events", len(evs))
	}
	s := d.Stats()
	if s.LateRecords != 1 || s.SequenceRestarts != 0 {
		t.Fatalf("late=%d restarts=%d, want 1 and 0", s.LateRecords, s.SequenceRestarts)
	}
}

func TestDroppedRecordsDoNotKeepStateAlive(t *testing.T) {
	now := time.Unix(1000, 0)
	d := New()
	d.nowFn = func() time.Time { return now }
	enc := newBlockEncoder()
	ingestRequests(d, enc, 0x53, 0, 3, "a")

	for i := 0; i < 10; i++ {
		now = now.Add(10 * time.Second)
		d.Ingest(rec(0x53, DirEgress, 1, 3, enc.encode(reqFields("GET", "/dup")...)))
	}
	d.Sweep()
	if s := d.Stats(); s.Conns != 0 {
		t.Fatalf("idle direction kept alive by dropped records: %+v", s)
	}
}

func TestARestartedConnectionDoesNotAnswerTheOldConnectionsRequests(t *testing.T) {
	d := New()
	oldReq, oldResp := newBlockEncoder(), newBlockEncoder()
	d.Ingest(rec(0x54, DirEgress, 0, 1, oldReq.encode(reqFields("GET", "/old/1")...)))
	d.Ingest(rec(0x54, DirEgress, 1, 3, oldReq.encode(reqFields("GET", "/old/3")...)))
	d.Ingest(rec(0x54, DirIngress, 0, 1, oldResp.encode(hf(":status", "200"))))

	ev := singleEvent(t, d.Ingest(rec(0x54, DirIngress, 0, 3, newBlockEncoder().encode(hf(":status", "404")))))
	if ev.Target != "404" || ev.LatencyNS != 0 {
		t.Fatalf("new connection's response = %+v; it was paired with the old connection's request", ev)
	}
	if s := d.Stats(); s.SequenceRestarts != 1 || s.Streams != 0 {
		t.Fatalf("stats = %+v; the old connection's request must be forgotten", s)
	}
}

func TestARestartKeepsTheNewConnectionsOwnRequests(t *testing.T) {
	d := New()
	oldReq, oldResp := newBlockEncoder(), newBlockEncoder()
	d.Ingest(rec(0x55, DirEgress, 0, 1, oldReq.encode(reqFields("GET", "/old/1")...)))
	d.Ingest(rec(0x55, DirEgress, 1, 3, oldReq.encode(reqFields("GET", "/old/3")...)))
	d.Ingest(rec(0x55, DirIngress, 0, 1, oldResp.encode(hf(":status", "200"))))

	newReq := newBlockEncoder()
	d.Ingest(rec(0x55, DirEgress, 0, 1, newReq.encode(reqFields("GET", "/new/1")...)))
	if s := d.Stats(); s.Streams != 2 {
		t.Fatalf("streams = %d; the old request may still be answered until the response side restarts", s.Streams)
	}

	ev := singleEvent(t, d.Ingest(rec(0x55, DirIngress, 0, 1, newBlockEncoder().encode(hf(":status", "201")))))
	if ev.Target != "GET /new/1" {
		t.Fatalf("new connection's response target = %q, want its own request", ev.Target)
	}
	if s := d.Stats(); s.SequenceRestarts != 2 || s.Streams != 0 {
		t.Fatalf("stats = %+v; the old connection's unanswered request must be forgotten", s)
	}
}

func TestARestartReleasesTheOldConnectionsHeldGRPCResponse(t *testing.T) {
	d := New()
	req, resp := newBlockEncoder(), newBlockEncoder()
	d.Ingest(rec(0x56, DirEgress, 0, 1, req.encode(reqFields("POST", "/pkg.Svc/Old", grpcType)...)))
	d.Ingest(rec(0x56, DirIngress, 0, 1, resp.encode(hf(":status", "200"), grpcType)))

	evs := d.Ingest(rec(0x56, DirIngress, 0, 3, newBlockEncoder().encode(hf(":status", "200"))))
	if len(evs) != 2 || evs[0].Target != "POST /pkg.Svc/Old" || evs[0].Details != "200" {
		t.Fatalf("events = %+v; the old call's held response must be released first", evs)
	}

	trailers := rec(0x56, DirIngress, 1, 1, newBlockEncoder().encode(hf("grpc-status", "0")))
	ev := singleEvent(t, d.Ingest(trailers))
	if ev.Target != "grpc-status 0" {
		t.Fatalf("new connection's trailers = %+v; they finished the old connection's call", ev)
	}
}

func TestAStreamMissingFromTheTableIsNotEndedByARestart(t *testing.T) {
	if endedByRestart(nil, DirIngress, 1) {
		t.Fatal("a missing stream was reported as ended")
	}
}
