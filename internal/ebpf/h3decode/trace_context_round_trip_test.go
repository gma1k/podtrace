package h3decode

import (
	"testing"

	"github.com/gma1k/podtrace/internal/tracing/extractor"
)

func TestTraceParentSurvivesCapturedHeaders(t *testing.T) {
	const tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
	d := NewDecoder([]string{"content-type", "x-request-id"})
	tx, ok := d.ParseRecord(buildRecordFull(1, 200, true, "GET", "/x", tp, 0, 0, 0, nil,
		[]string{"application/json", "req-42"}))
	if !ok {
		t.Fatal("ParseRecord returned false")
	}
	req := tx.Events()[0]
	tc := extractor.NewHTTPExtractor().ExtractFromRawHeaders(req.Details)
	if tc == nil {
		t.Fatalf("no trace context recovered from Details %q", req.Details)
	}
	if tc.TraceID != "0af7651916cd43dd8448eb211c80319c" || tc.ParentSpanID != "b7ad6b7169203331" {
		t.Fatalf("trace context = %+v", tc)
	}
}
