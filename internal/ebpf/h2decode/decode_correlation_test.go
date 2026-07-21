package h2decode

import (
	"testing"

	"github.com/podtrace/podtrace/internal/events"
)

func TestIngestNil(t *testing.T) {
	if evs := New().Ingest(nil); evs != nil {
		t.Fatalf("Ingest(nil) = %v, want nil", evs)
	}
}

func TestAssemblyBoundDropsBlock(t *testing.T) {
	d := New()
	d.maxAssembly = 100

	mid := &RawRecord{ConnID: 1, Direction: DirEgress, Seq: 0, StreamID: 1,
		FragLen: 60, Frag: make([]byte, 60)}
	end := &RawRecord{ConnID: 1, Direction: DirEgress, Seq: 1, StreamID: 1,
		FragLen: 60, Frag: make([]byte, 60), Flags: flagEndHeaders}

	if evs := d.Ingest(mid); len(evs) != 0 {
		t.Fatalf("first fragment emitted %d events", len(evs))
	}
	if evs := d.Ingest(end); len(evs) != 0 {
		t.Fatalf("over-cap block emitted %d events", len(evs))
	}
	if d.Stats().DecodeErrors != 1 {
		t.Fatalf("DecodeErrors = %d, want 1", d.Stats().DecodeErrors)
	}
}

func TestRequestWithoutMethodDefaultsToGet(t *testing.T) {
	d := New()
	enc := newBlockEncoder()
	block := enc.encode(hf(":path", "/only"))
	ev := singleEvent(t, d.Ingest(rec(1, DirEgress, 0, 1, block)))
	if ev.Type != events.EventHTTPReq || ev.Target != "GET /only" {
		t.Fatalf("target = %q type = %v, want GET /only request", ev.Target, ev.Type)
	}
}

func TestStreamZeroNotRemembered(t *testing.T) {
	d := New()
	enc := newBlockEncoder()
	block := enc.encode(reqFields("GET", "/x")...)
	singleEvent(t, d.Ingest(rec(2, DirEgress, 0, 0, block)))
	if s := d.Stats(); s.Streams != 0 {
		t.Fatalf("stream 0 was remembered: %+v", s)
	}
}

func TestUncorrelatedResponseWithTraceparent(t *testing.T) {
	d := New()
	enc := newBlockEncoder()
	tp := "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	block := enc.encode(hf(":status", "200"), hf("traceparent", tp))
	ev := singleEvent(t, d.Ingest(rec(3, DirIngress, 0, 1, block)))
	if ev.Type != events.EventHTTPResp {
		t.Fatalf("type = %v, want response", ev.Type)
	}
	if ev.Details != "traceparent: "+tp {
		t.Fatalf("details = %q, want traceparent line", ev.Details)
	}
	if ev.Target != "200" {
		t.Fatalf("target = %q, want 200 (uncorrelated)", ev.Target)
	}
}

func TestGrpcTrailerNonNumericAndUncorrelated(t *testing.T) {
	d := New()
	enc := newBlockEncoder()
	block := enc.encode(hf("grpc-status", "abc"))
	ev := singleEvent(t, d.Ingest(rec(4, DirIngress, 0, 1, block)))
	if ev.Type != events.EventHTTPResp {
		t.Fatalf("type = %v, want response", ev.Type)
	}
	if ev.Error != 0 {
		t.Fatalf("non-numeric grpc-status set Error = %d, want 0", ev.Error)
	}
	if ev.Target != "grpc-status abc" {
		t.Fatalf("target = %q, want grpc-status abc", ev.Target)
	}
}

func TestAnonymousRequestOnIngressUsesEgressRole(t *testing.T) {
	d := New()
	const conn = 5

	respEnc := newBlockEncoder()
	singleEvent(t, d.Ingest(rec(conn, DirEgress, 0, 99, respEnc.encode(hf(":status", "200")))))

	reqEnc := newBlockEncoder()
	_ = reqEnc.encode(hf("x-marker", "m"))
	steady := reqEnc.encode(hf("x-marker", "m"))

	reqEv := singleEvent(t, d.Ingest(rec(conn, DirIngress, 0, 1, steady)))
	if reqEv.Type != events.EventHTTPReq {
		t.Fatalf("type = %v, want request", reqEv.Type)
	}
	if reqEv.Target != "? "+unknownPathPlaceholder {
		t.Fatalf("target = %q, want %q", reqEv.Target, "? "+unknownPathPlaceholder)
	}
	if d.Stats().AnonymousRequests != 1 {
		t.Fatalf("AnonymousRequests = %d, want 1", d.Stats().AnonymousRequests)
	}

	steady2 := reqEnc.encode(hf("x-marker", "m"))
	if evs := d.Ingest(rec(conn, DirIngress, 1, 1, steady2)); len(evs) != 0 {
		t.Fatalf("second anonymous block on the stream emitted %d events, want 0", len(evs))
	}
	if d.Stats().AnonymousRequests != 1 {
		t.Fatalf("AnonymousRequests = %d after duplicate, want 1", d.Stats().AnonymousRequests)
	}
}

func TestGrpcTrailerCorrelatesWithOpenStream(t *testing.T) {
	d := New()
	reqEnc := newBlockEncoder()
	req := &RawRecord{ConnID: 6, Direction: DirEgress, Seq: 0, StreamID: 1,
		Timestamp: 1000, Transport: 2, Flags: flagEndHeaders}
	reqBlock := reqEnc.encode(reqFields("POST", "/pkg.Svc/Do")...)
	req.FragLen = uint16(len(reqBlock))
	req.Frag = reqBlock
	singleEvent(t, d.Ingest(req))

	trailerEnc := newBlockEncoder()
	trailer := &RawRecord{ConnID: 6, Direction: DirIngress, Seq: 0, StreamID: 1,
		Timestamp: 1500, Transport: 2, Flags: flagEndHeaders}
	trailerBlock := trailerEnc.encode(hf("grpc-status", "9"))
	trailer.FragLen = uint16(len(trailerBlock))
	trailer.Frag = trailerBlock

	ev := singleEvent(t, d.Ingest(trailer))
	if ev.Target != "POST /pkg.Svc/Do" {
		t.Fatalf("trailer target = %q, want correlated request endpoint", ev.Target)
	}
	if ev.LatencyNS != 500 {
		t.Fatalf("latency = %d, want 500", ev.LatencyNS)
	}
	if ev.CorrelationID != 1000 || ev.Error != 9 {
		t.Fatalf("correlation = %d error = %d, want 1000/9", ev.CorrelationID, ev.Error)
	}
	if d.Stats().Streams != 0 {
		t.Fatalf("correlated trailer did not close the stream: %+v", d.Stats())
	}
}

func TestOtherDirection(t *testing.T) {
	if otherDirection(DirEgress) != DirIngress {
		t.Fatal("otherDirection(egress) != ingress")
	}
	if otherDirection(DirIngress) != DirEgress {
		t.Fatal("otherDirection(ingress) != egress")
	}
}

func TestSkipGapWithEmptyPendingIsNoOp(t *testing.T) {
	d := New()
	st := &dirState{
		dec:     &lateJoinDecoder{},
		nextSeq: 7,
		pending: make(map[uint32]*RawRecord),
	}
	d.skipGapLocked(st)
	if st.nextSeq != 7 || d.gapsSkipped != 0 {
		t.Fatalf("empty-pending gap skip mutated state: nextSeq=%d gaps=%d", st.nextSeq, d.gapsSkipped)
	}
}
