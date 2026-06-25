package agent

import (
	"testing"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/tracing/extractor"
)

// newStitchExporter builds a minimal sdkEventExporter exercising only the
// trace-context plumbing.
func newStitchExporter() *sdkEventExporter {
	return &sdkEventExporter{extractor: extractor.NewHTTPExtractor()}
}

const (
	stitchTraceID  = "0af7651916cd43dd8448eb211c80319c"
	stitchSpanID   = "b7ad6b7169203331"
	stitchTracePar = "traceparent: 00-" + stitchTraceID + "-" + stitchSpanID + "-01"
)

// TestRemoteParent_HTTPReqWithTraceparent: an HTTP request event whose Details
// carries a captured W3C traceparent must yield a remote parent span context
// under the app's trace, with the app's span as parent.
func TestRemoteParent_HTTPReqWithTraceparent(t *testing.T) {
	e := newStitchExporter()
	ev := &events.Event{Type: events.EventHTTPReq, Target: "GET /api", Details: stitchTracePar}

	sc, ok := e.remoteParent(ev)
	if !ok {
		t.Fatal("expected a valid remote parent span context, got none")
	}
	if sc.TraceID().String() != stitchTraceID {
		t.Errorf("TraceID = %s, want %s", sc.TraceID(), stitchTraceID)
	}
	if sc.SpanID().String() != stitchSpanID {
		t.Errorf("parent SpanID = %s, want app span %s", sc.SpanID(), stitchSpanID)
	}
	if !sc.IsRemote() {
		t.Error("parent span context should be marked remote")
	}
	if !sc.IsSampled() {
		t.Error("flags 01 should mark the context sampled")
	}
}

// TestRemoteParent_NoContext: events without trace context (no traceparent,
// non-HTTP types, or a status-only response) stay standalone roots.
func TestRemoteParent_NoContext(t *testing.T) {
	e := newStitchExporter()
	cases := []struct {
		name string
		ev   *events.Event
	}{
		{"http req, no traceparent", &events.Event{Type: events.EventHTTPReq, Details: ""}},
		{"http resp, status only", &events.Event{Type: events.EventHTTPResp, Details: "200"}},
		{"non-http event ignored", &events.Event{Type: events.EventDNS, Details: stitchTracePar}},
		{"colon detail, not a trace header", &events.Event{Type: events.EventHTTPReq, Details: "1.2.3.4:53"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, ok := e.remoteParent(c.ev); ok {
				t.Errorf("%s: expected no remote parent", c.name)
			}
		})
	}
}