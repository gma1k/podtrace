package extractor

import "testing"

func TestExtractSplunk_SameRequestIDCorrelates(t *testing.T) {
	e := NewHTTPExtractor()

	a := e.ExtractFromHeaders(map[string]string{"x-splunk-requestid": "req-abc"})
	b := e.ExtractFromHeaders(map[string]string{"x-splunk-requestid": "req-abc"})
	c := e.ExtractFromHeaders(map[string]string{"x-splunk-requestid": "req-xyz"})

	if a == nil || b == nil || c == nil {
		t.Fatal("expected a trace context for each x-splunk-requestid header")
	}
	if a.TraceID != b.TraceID {
		t.Fatalf("same request id produced different traces: %s vs %s", a.TraceID, b.TraceID)
	}
	if a.TraceID == c.TraceID {
		t.Fatalf("different request ids collided on trace %s", a.TraceID)
	}
	if a.SpanID == b.SpanID {
		t.Fatal("each event must still get a unique span id")
	}
	if a.State != "req-abc" {
		t.Fatalf("request id must be preserved in State, got %q", a.State)
	}
}
