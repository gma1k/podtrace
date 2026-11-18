package h2decode

import (
	"testing"

	"github.com/gma1k/podtrace/internal/tracing/extractor"
)

const roundTripTraceParent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

func assertTraceParentRecoverable(t *testing.T, details string) {
	t.Helper()
	tc := extractor.NewHTTPExtractor().ExtractFromRawHeaders(details)
	if tc == nil {
		t.Fatalf("no trace context recovered from Details %q", details)
	}
	if tc.TraceID != "0af7651916cd43dd8448eb211c80319c" || tc.ParentSpanID != "b7ad6b7169203331" {
		t.Fatalf("trace context = %+v from Details %q", tc, details)
	}
}

func TestTraceParentSurvivesCapturedRequestHeaders(t *testing.T) {
	d := New()
	d.SetCaptureHeaders([]string{"content-type", "x-request-id"})
	be := newBlockEncoder()
	ev := singleEvent(t, d.Ingest(rec(90, DirEgress, 0, 1, be.encode(reqFields("POST", "/x",
		hf("traceparent", roundTripTraceParent),
		hf("content-type", "application/json"),
		hf("x-request-id", "r-1"))...))))
	assertTraceParentRecoverable(t, ev.Details)
}

func TestTraceParentSurvivesCapturedResponseHeaders(t *testing.T) {
	d := New()
	d.SetCaptureHeaders([]string{"content-type"})
	be, ibe := newBlockEncoder(), newBlockEncoder()
	d.Ingest(rec(91, DirEgress, 0, 1, be.encode(reqFields("GET", "/x")...)))
	ev := singleEvent(t, d.Ingest(rec(91, DirIngress, 0, 1, ibe.encode(
		hf(":status", "200"),
		hf("traceparent", roundTripTraceParent),
		hf("content-type", "text/plain")))))
	assertTraceParentRecoverable(t, ev.Details)
}

func TestTraceParentSurvivesAHeldGRPCResponse(t *testing.T) {
	d := New()
	be, ibe := newBlockEncoder(), newBlockEncoder()
	d.Ingest(rec(92, DirIngress, 0, 1, be.encode(reqFields("POST", "/pkg.Svc/Do", grpcType)...)))
	if evs := d.Ingest(rec(92, DirEgress, 0, 1, ibe.encode(
		hf(":status", "200"), grpcType, hf("traceparent", roundTripTraceParent)))); len(evs) != 0 {
		t.Fatalf("response HEADERS of a gRPC call emitted %d events before its trailers", len(evs))
	}
	ev := singleEvent(t, d.Ingest(rec(92, DirEgress, 1, 1, ibe.encode(hf("grpc-status", "0")))))
	assertTraceParentRecoverable(t, ev.Details)
}
