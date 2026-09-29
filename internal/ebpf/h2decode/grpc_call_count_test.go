package h2decode

import (
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

var grpcType = hf("content-type", "application/grpc")

func grpcCall(t *testing.T, d *Decoder, conn uint64, grpcStatus string) []*events.Event {
	t.Helper()
	be, ibe := newBlockEncoder(), newBlockEncoder()
	var out []*events.Event
	out = append(out, d.Ingest(rec(conn, DirIngress, 0, 1, be.encode(reqFields("POST", "/pkg.Svc/Do", grpcType)...)))...)
	out = append(out, d.Ingest(rec(conn, DirEgress, 0, 1, ibe.encode(hf(":status", "200"), grpcType)))...)
	later := rec(conn, DirEgress, 1, 1, ibe.encode(hf("grpc-status", grpcStatus)))
	later.Timestamp = 5000
	out = append(out, d.Ingest(later)...)
	return out
}

func responses(evs []*events.Event) []*events.Event {
	var out []*events.Event
	for _, ev := range evs {
		if ev.Type == events.EventHTTPResp {
			out = append(out, ev)
		}
	}
	return out
}

func TestAGRPCCallIsOneResponseEndedByItsTrailers(t *testing.T) {
	resp := responses(grpcCall(t, New(), 70, "0"))
	if len(resp) != 1 {
		t.Fatalf("%d response events for one gRPC call; its HEADERS and trailers are one call", len(resp))
	}
	ev := resp[0]
	if ev.Target != "POST /pkg.Svc/Do" || ev.Details != "200\ngrpc-status: 0" || ev.Error != 0 {
		t.Errorf("response = %+v", ev)
	}
	if ev.LatencyNS != 4000 || ev.CorrelationID != 1000 {
		t.Errorf("latency = %d, correlation = %d; the call ends at its trailers", ev.LatencyNS, ev.CorrelationID)
	}
	if code, ok := ev.ResponseStatus(); !ok || code != 200 {
		t.Errorf("ResponseStatus = %d, %v", code, ok)
	}
	if !IsGRPCResponse(ev) {
		t.Error("the call's response is not recognised as gRPC")
	}
}

func TestAFailedGRPCCallCountsOnceAsAnError(t *testing.T) {
	resp := responses(grpcCall(t, New(), 71, "13"))
	if len(resp) != 1 || resp[0].Error != 13 || !resp[0].IsError() {
		t.Fatalf("responses = %+v; a failed call is one response carrying its grpc-status", resp)
	}
}

func TestALateJoinedGRPCCallIsStillOneResponse(t *testing.T) {
	d := New()
	ibe := newBlockEncoder()
	if evs := d.Ingest(rec(72, DirEgress, 0, 1, ibe.encode(hf(":status", "200"), grpcType))); len(evs) != 0 {
		t.Fatalf("the HEADERS of a call whose request was never seen emitted %d events", len(evs))
	}
	ev := singleEvent(t, d.Ingest(rec(72, DirEgress, 1, 1, ibe.encode(hf("grpc-status", "0")))))
	if ev.Target != "200" || ev.Details != "200\ngrpc-status: 0" || ev.LatencyNS != 0 {
		t.Errorf("response = %+v", ev)
	}
}

func TestAGRPCRequestWithoutAResponseTypeIsStillHeld(t *testing.T) {
	d := New()
	be, ibe := newBlockEncoder(), newBlockEncoder()
	d.Ingest(rec(73, DirIngress, 0, 1, be.encode(reqFields("POST", "/pkg.Svc/Do", grpcType)...)))
	if evs := d.Ingest(rec(73, DirEgress, 0, 1, ibe.encode(hf(":status", "200")))); len(evs) != 0 {
		t.Errorf("a gRPC call's HEADERS emitted %d events before its trailers", len(evs))
	}
}

func TestAHeldGRPCResponseCarriesItsTraceparentAndHeaders(t *testing.T) {
	d := New()
	d.SetCaptureHeaders([]string{"x-request-id"})
	ibe := newBlockEncoder()
	d.Ingest(rec(74, DirEgress, 0, 1, ibe.encode(hf(":status", "503"), grpcType,
		hf("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"), hf("x-request-id", "r-1"))))
	ev := singleEvent(t, d.Ingest(rec(74, DirEgress, 1, 1, ibe.encode(hf("grpc-status", "14")))))
	want := "503\ntraceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01\nx-request-id: r-1\ngrpc-status: 14"
	if ev.Details != want || ev.Error != 503 {
		t.Errorf("details = %q, error = %d; want %q and the 5xx kept over grpc-status", ev.Details, ev.Error, want)
	}
}

func TestACallCutOffBeforeItsTrailersIsCountedWhenItsConnectionCloses(t *testing.T) {
	d := New()
	ibe := newBlockEncoder()
	d.Ingest(rec(75, DirEgress, 0, 1, ibe.encode(hf(":status", "200"), grpcType)))
	d.Ingest(rec(76, DirEgress, 0, 1, newBlockEncoder().encode(hf(":status", "200"), grpcType)))
	evs := d.Evict(75)
	if len(evs) != 1 || evs[0].Details != "200" {
		t.Fatalf("evicted %+v; the cut-off call counts once, without an outcome", evs)
	}
	if d.Stats().Streams != 1 {
		t.Errorf("streams = %d; another connection's call was dropped", d.Stats().Streams)
	}
	if len(d.Evict(77)) != 0 {
		t.Error("an unknown connection returned events")
	}
}

func TestAHeldGRPCResponseIsFlushedWhenItExpires(t *testing.T) {
	d := New()
	now := time.Now()
	d.nowFn = func() time.Time { return now }
	d.Ingest(rec(78, DirEgress, 0, 1, newBlockEncoder().encode(hf(":status", "200"), grpcType)))
	be := newBlockEncoder()
	d.Ingest(rec(79, DirIngress, 0, 1, be.encode(reqFields("GET", "/x")...)))
	now = now.Add(2 * defaultTTL)
	evs := d.Sweep()
	if len(evs) != 1 || evs[0].Details != "200" {
		t.Errorf("swept %+v; only the held gRPC response is an event", evs)
	}
}

func TestHoldingAResponseRespectsTheStreamBound(t *testing.T) {
	d := New()
	d.maxStreams = 1
	be := newBlockEncoder()
	d.Ingest(rec(80, DirIngress, 0, 1, be.encode(reqFields("GET", "/old")...)))
	d.Ingest(rec(81, DirEgress, 0, 1, newBlockEncoder().encode(hf(":status", "200"), grpcType)))
	if d.Stats().Streams != 1 {
		t.Errorf("streams = %d against a bound of 1", d.Stats().Streams)
	}
}

func TestOnlyADecodedResponseWithAGRPCStatusIsGRPC(t *testing.T) {
	for _, ev := range []*events.Event{
		nil,
		{Type: events.EventHTTPReq, Details: "grpc-status: 0"},
		{Type: events.EventHTTPResp, Details: "200"},
		{Type: events.EventHTTPResp, Details: "200\nx-grpc-status: 1"},
	} {
		if IsGRPCResponse(ev) {
			t.Errorf("%+v was taken for a gRPC response", ev)
		}
	}
	if !IsGRPCResponse(&events.Event{Type: events.EventHTTPResp, Details: "grpc-status: 0"}) {
		t.Error("a trailers-only response was not recognised")
	}
}
