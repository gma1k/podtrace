package h3decode

import (
	"encoding/binary"
	"testing"

	"github.com/podtrace/podtrace/internal/events"
)

// buildRecord assembles a wire-format struct h3_txn_record, mirroring
// bpf/http3l7.c.
func buildRecord(latencyNS uint64, status uint16, isClient bool, method, path string) []byte {
	return buildRecordTP(latencyNS, status, isClient, method, path, "")
}

func buildRecordTP(latencyNS uint64, status uint16, isClient bool, method, path, tp string) []byte {
	buf := make([]byte, recordSize)
	binary.LittleEndian.PutUint64(buf[0:8], 1000)       // timestamp
	binary.LittleEndian.PutUint64(buf[8:16], latencyNS) // latency
	binary.LittleEndian.PutUint64(buf[16:24], 222)      // cgroup
	binary.LittleEndian.PutUint32(buf[24:28], 4242)     // pid
	binary.LittleEndian.PutUint16(buf[28:30], status)
	if isClient {
		buf[30] = 1
	}
	m := method
	if len(m) > methodMax {
		m = m[:methodMax]
	}
	p := path
	if len(p) > pathMax {
		p = p[:pathMax]
	}
	if len(tp) > tpMax {
		tp = tp[:tpMax]
	}
	buf[31] = uint8(len(m))
	binary.LittleEndian.PutUint16(buf[32:34], uint16(len(p)))
	buf[34] = uint8(len(tp))
	copy(buf[methodOffset:], m)
	copy(buf[pathOffset:], p)
	copy(buf[tpOffset:], tp)
	return buf
}

func TestParseRecord(t *testing.T) {
	tx, ok := ParseRecord(buildRecord(1_500_000, 200, true, "GET", "/hello"))
	if !ok {
		t.Fatal("ParseRecord returned false")
	}
	if tx.Method != "GET" || tx.Path != "/hello" || tx.Status != 200 || !tx.IsClient {
		t.Fatalf("unexpected txn: %+v", tx)
	}
	if tx.LatencyNS != 1_500_000 {
		t.Fatalf("unexpected latency: %d", tx.LatencyNS)
	}
}

func TestParseRecordTooShort(t *testing.T) {
	if _, ok := ParseRecord(make([]byte, 50)); ok {
		t.Fatal("expected ParseRecord to reject a short sample")
	}
}

func TestEventsPairedWithLatency(t *testing.T) {
	tx, _ := ParseRecord(buildRecord(2_000_000, 200, true, "GET", "/hello"))
	evs := tx.Events()
	if len(evs) != 2 {
		t.Fatalf("expected 2 events, got %d", len(evs))
	}
	req, resp := evs[0], evs[1]
	if req.Type != events.EventHTTPReq || req.Target != "GET /hello" {
		t.Fatalf("unexpected request event: %+v", req)
	}
	// The response is reported against its endpoint (not a bare status) and
	// carries the measured latency.
	if resp.Type != events.EventHTTPResp || resp.Target != "GET /hello" {
		t.Fatalf("unexpected response target: %+v", resp)
	}
	if resp.Details != "200" || resp.LatencyNS != 2_000_000 {
		t.Fatalf("unexpected response status/latency: %+v", resp)
	}
	if resp.HTTPProtoLabel() != "HTTP/3" || resp.HTTPScheme() != "https" {
		t.Fatalf("unexpected transport: label=%q scheme=%q", resp.HTTPProtoLabel(), resp.HTTPScheme())
	}
}

// The request and response events of one transaction must carry the same
// non-zero CorrelationID so the tracing layer can join the context-bearing
// request with the duration-bearing response into a single span.
func TestEventsShareCorrelationID(t *testing.T) {
	tx, _ := ParseRecord(buildRecord(2_000_000, 200, true, "GET", "/hello"))
	evs := tx.Events()
	if len(evs) != 2 {
		t.Fatalf("expected 2 events, got %d", len(evs))
	}
	req, resp := evs[0], evs[1]
	if req.CorrelationID == 0 {
		t.Fatal("request CorrelationID is 0")
	}
	if req.CorrelationID != resp.CorrelationID {
		t.Errorf("correlation mismatch: req=%d resp=%d", req.CorrelationID, resp.CorrelationID)
	}
	if req.CorrelationID != req.Timestamp {
		t.Errorf("CorrelationID %d should equal request start ts %d", req.CorrelationID, req.Timestamp)
	}
}

func TestTraceparentSurfacedInDetails(t *testing.T) {
	const tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	tx, ok := ParseRecord(buildRecordTP(1_000_000, 200, true, "GET", "/hello", tp))
	if !ok {
		t.Fatal("ParseRecord returned false")
	}
	if tx.Traceparent != tp {
		t.Fatalf("traceparent = %q, want %q", tx.Traceparent, tp)
	}
	req := tx.Events()[0]
	if req.Details != "traceparent: "+tp {
		t.Fatalf("request Details = %q, want traceparent prefix", req.Details)
	}
}

func TestNoTraceparentLeavesDetailsEmpty(t *testing.T) {
	tx, _ := ParseRecord(buildRecord(1_000_000, 200, true, "GET", "/hello"))
	if tx.Traceparent != "" {
		t.Fatalf("expected empty traceparent, got %q", tx.Traceparent)
	}
	if got := tx.Events()[0].Details; got != "" {
		t.Fatalf("expected empty request Details, got %q", got)
	}
}

func TestEvents5xxSetsError(t *testing.T) {
	tx, _ := ParseRecord(buildRecord(1, 503, false, "GET", "/boom"))
	resp := tx.Events()[1]
	if resp.Error != 503 {
		t.Fatalf("expected 5xx to set Error, got %d", resp.Error)
	}
}

func TestEventsDefaultMethod(t *testing.T) {
	tx, _ := ParseRecord(buildRecord(1, 200, true, "", "/x"))
	if got := tx.Events()[0].Target; got != "GET /x" {
		t.Fatalf("expected empty method to default to GET, got %q", got)
	}
}

// buildRecordFull extends buildRecordTP with peer, capture-header slots, and
// flags, mirroring the full struct h3_txn_record.
func buildRecordFull(latencyNS uint64, status uint16, isClient bool, method, path, tp string,
	flags uint8, peerFamily uint8, peerPort uint16, peerAddr []byte, hdrVals []string) []byte {
	buf := buildRecordTP(latencyNS, status, isClient, method, path, tp)
	buf[35] = flags
	buf[36] = peerFamily
	binary.LittleEndian.PutUint16(buf[38:40], peerPort)
	copy(buf[peerOffset:peerOffset+16], peerAddr)
	for i, v := range hdrVals {
		if i >= hdrSlots {
			break
		}
		if len(v) > hdrValMax {
			v = v[:hdrValMax]
		}
		buf[hdrLenOffset+i] = uint8(len(v))
		copy(buf[hdrValOffset+i*hdrValMax:], v)
	}
	return buf
}

func TestParseRecordPeerV4(t *testing.T) {
	rec := buildRecordFull(1, 200, true, "GET", "/x", "", 0, 2, 8443,
		[]byte{10, 1, 2, 3}, nil)
	tx, ok := ParseRecord(rec)
	if !ok {
		t.Fatal("ParseRecord returned false")
	}
	if tx.PeerIP != "10.1.2.3" || tx.PeerPort != 8443 {
		t.Fatalf("peer = %q:%d, want 10.1.2.3:8443", tx.PeerIP, tx.PeerPort)
	}
	for _, ev := range tx.Events() {
		if ev.PeerDstIP != "10.1.2.3" || ev.PeerDstPort != 8443 {
			t.Fatalf("event peer = %q:%d", ev.PeerDstIP, ev.PeerDstPort)
		}
	}
}

func TestParseRecordPeerV4MappedV6(t *testing.T) {
	addr := make([]byte, 16)
	copy(addr[10:], []byte{0xff, 0xff, 192, 168, 0, 7})
	tx, _ := ParseRecord(buildRecordFull(1, 200, false, "GET", "/x", "", 0, 10, 443, addr, nil))
	if tx.PeerIP != "192.168.0.7" {
		t.Fatalf("expected v4-mapped normalization, got %q", tx.PeerIP)
	}
}

func TestParseRecordNoPeer(t *testing.T) {
	tx, _ := ParseRecord(buildRecord(1, 200, true, "GET", "/x"))
	if tx.PeerIP != "" || tx.PeerPort != 0 {
		t.Fatalf("expected empty peer, got %q:%d", tx.PeerIP, tx.PeerPort)
	}
	if ev := tx.Events()[0]; ev.PeerDstIP != "" {
		t.Fatalf("expected event without peer, got %q", ev.PeerDstIP)
	}
}

func TestDecoderCaptureHeaders(t *testing.T) {
	d := NewDecoder([]string{"content-type", "x-request-id"})
	rec := buildRecordFull(1, 200, true, "GET", "/x", "", 0, 0, 0, nil,
		[]string{"application/json", "req-42"})
	tx, ok := d.ParseRecord(rec)
	if !ok {
		t.Fatal("ParseRecord returned false")
	}
	if len(tx.Headers) != 2 || tx.Headers[0].Value != "application/json" ||
		tx.Headers[1].Name != "x-request-id" {
		t.Fatalf("unexpected headers: %+v", tx.Headers)
	}
	req := tx.Events()[0]
	want := "content-type: application/json\nx-request-id: req-42"
	if req.Details != want {
		t.Fatalf("request Details = %q, want %q", req.Details, want)
	}
	resp := tx.Events()[1]
	if resp.Details != "200\ncontent-type: application/json\nx-request-id: req-42" {
		t.Fatalf("response Details = %q", resp.Details)
	}
}

func TestDecoderEmptySlotSkipped(t *testing.T) {
	d := NewDecoder([]string{"content-type", "x-request-id"})
	rec := buildRecordFull(1, 200, true, "GET", "/x", "", 0, 0, 0, nil,
		[]string{"", "req-9"})
	tx, _ := d.ParseRecord(rec)
	if len(tx.Headers) != 1 || tx.Headers[0].Name != "x-request-id" {
		t.Fatalf("unexpected headers: %+v", tx.Headers)
	}
}

func TestRequestOnlyFlagEmitsSingleEvent(t *testing.T) {
	rec := buildRecordFull(0, 0, true, "GET", "/curl", "", FlagRequestOnly, 0, 0, nil, nil)
	tx, _ := ParseRecord(rec)
	evs := tx.Events()
	if len(evs) != 1 || evs[0].Type != events.EventHTTPReq {
		t.Fatalf("expected single request event, got %+v", evs)
	}
}

func TestResponseOnlyFlagEmitsSingleEvent(t *testing.T) {
	rec := buildRecordFull(0, 404, false, "", "", "", FlagResponseOnly, 0, 0, nil, nil)
	tx, _ := ParseRecord(rec)
	evs := tx.Events()
	if len(evs) != 1 || evs[0].Type != events.EventHTTPResp {
		t.Fatalf("expected single response event, got %+v", evs)
	}
	if evs[0].Target != "HTTP/3" {
		t.Fatalf("expected generic target for response-only event, got %q", evs[0].Target)
	}
	if evs[0].Details != "404" {
		t.Fatalf("unexpected details %q", evs[0].Details)
	}
}

func TestAbortedFlagMarksResponse(t *testing.T) {
	rec := buildRecordFull(3_000_000, 0, false, "GET", "/panics", "", FlagAborted, 0, 0, nil, nil)
	tx, _ := ParseRecord(rec)
	evs := tx.Events()
	if len(evs) != 2 {
		t.Fatalf("expected paired events for aborted txn, got %d", len(evs))
	}
	resp := evs[1]
	if resp.Details != "aborted" {
		t.Fatalf("aborted response Details = %q", resp.Details)
	}
	if resp.Target != "GET /panics" || resp.LatencyNS != 3_000_000 {
		t.Fatalf("unexpected aborted response: %+v", resp)
	}
}

func TestAdapterPairedTTFB(t *testing.T) {
	// C-library adapter pair: request + first-inbound-byte, no readable status.
	rec := buildRecordFull(4_000_000, 0, true, "GET", "/curl", "", 0, 0, 0, nil, nil)
	tx, _ := ParseRecord(rec)
	evs := tx.Events()
	if len(evs) != 2 {
		t.Fatalf("expected paired events, got %d", len(evs))
	}
	resp := evs[1]
	if resp.LatencyNS != 4_000_000 {
		t.Fatalf("latency = %d", resp.LatencyNS)
	}
	if resp.Details != "" {
		t.Fatalf("status-0 pair must not render a status line, got %q", resp.Details)
	}
}
