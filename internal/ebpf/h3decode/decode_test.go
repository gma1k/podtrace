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
