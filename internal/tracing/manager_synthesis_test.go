package tracing

import (
	"testing"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/diagnose/tracker"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/tracing/extractor"
)

const (
	testAppTraceID = "0af7651916cd43dd8448eb211c80319c"
	testAppSpanID  = "b7ad6b7169203331"
)

func newTestManager(synthesize bool) *Manager {
	return &Manager{
		enabled:      true,
		extractor:    extractor.NewHTTPExtractor(),
		traceTracker: tracker.NewTraceTracker(),
		corr:         newCorrelationCache(config.MaxTraceContextCacheSize),
		synthesize:   synthesize,
	}
}

// httpReq/httpResp build the two events of one request: they share a
// CorrelationID and connection 4-tuple (as the eBPF/decoder layer emits), the
// request carries the inbound traceparent, the response carries only status +
// latency.
func httpReq(corr uint64, tsNS uint64, details string) *events.Event {
	return &events.Event{
		Type:          events.EventHTTPReq,
		Timestamp:     tsNS,
		CorrelationID: corr,
		PeerSrcIP:     "10.0.0.1", PeerSrcPort: 5000,
		PeerDstIP: "10.0.0.2", PeerDstPort: 80,
		Target:  "GET /hello",
		Details: details,
	}
}

func httpResp(corr uint64, tsNS, latencyNS uint64) *events.Event {
	return &events.Event{
		Type:          events.EventHTTPResp,
		Timestamp:     tsNS,
		LatencyNS:     latencyNS,
		CorrelationID: corr,
		PeerSrcIP:     "10.0.0.1", PeerSrcPort: 5000,
		PeerDstIP: "10.0.0.2", PeerDstPort: 80,
		Target:  "GET /hello",
		Details: "200",
	}
}

func onlySpan(t *testing.T, m *Manager) *tracker.Span {
	t.Helper()
	traces := m.traceTracker.SnapshotForExport(0, true)
	if len(traces) != 1 {
		t.Fatalf("expected 1 trace, got %d", len(traces))
	}
	if len(traces[0].Spans) != 1 {
		t.Fatalf("expected 1 span (req+resp collapsed), got %d", len(traces[0].Spans))
	}
	return traces[0].Spans[0]
}

// HN5: a request and its response collapse into ONE span with a real duration,
// hung under the application's span, with a minted (non-colliding) span id.
func TestProcessEvent_W3C_PairsIntoOneSpanWithDuration(t *testing.T) {
	m := newTestManager(false)
	tp := "traceparent: 00-" + testAppTraceID + "-" + testAppSpanID + "-01"
	m.ProcessEvent(httpReq(1000, 1000, tp), nil)
	m.ProcessEvent(httpResp(1000, 6000, 5000), nil)

	span := onlySpan(t, m)
	if span.TraceID != testAppTraceID {
		t.Errorf("TraceID = %s, want app trace %s", span.TraceID, testAppTraceID)
	}
	if span.ParentSpanID != testAppSpanID {
		t.Errorf("ParentSpanID = %s, want app span %s (podtrace is a child)", span.ParentSpanID, testAppSpanID)
	}
	if span.SpanID == "" || span.SpanID == testAppSpanID {
		t.Errorf("SpanID = %q, want a minted id distinct from the app span (no collision)", span.SpanID)
	}
	if span.Duration <= 0 {
		t.Errorf("Duration = %v, want > 0 (req+resp must collapse into one timed span)", span.Duration)
	}
}

// B3: podtrace must not reuse the app's x-b3-spanid as its own span id.
func TestProcessEvent_B3_NoSpanIDCollision(t *testing.T) {
	m := newTestManager(false)
	details := "x-b3-traceid: " + testAppTraceID + "\r\nx-b3-spanid: " + testAppSpanID
	m.ProcessEvent(httpReq(2000, 1000, details), nil)
	m.ProcessEvent(httpResp(2000, 4000, 3000), nil)

	span := onlySpan(t, m)
	if span.SpanID == testAppSpanID {
		t.Error("SpanID collides with the application's x-b3-spanid")
	}
	if span.ParentSpanID != testAppSpanID {
		t.Errorf("ParentSpanID = %s, want caller span %s", span.ParentSpanID, testAppSpanID)
	}
}

// Synthesis on: context-less correlated traffic mints a per-pod root span,
// still collapsing req+resp into one timed span.
func TestProcessEvent_Synthesize_RootSpanForContextlessTraffic(t *testing.T) {
	m := newTestManager(true)
	m.ProcessEvent(httpReq(3000, 1000, ""), nil) // no traceparent
	m.ProcessEvent(httpResp(3000, 9000, 8000), nil)

	span := onlySpan(t, m)
	if span.TraceID == "" {
		t.Error("synthesized span has no trace id")
	}
	if span.ParentSpanID != "" {
		t.Errorf("synthesized span should be a root (no parent), got parent %s", span.ParentSpanID)
	}
	if span.Duration <= 0 {
		t.Errorf("Duration = %v, want > 0", span.Duration)
	}
}

// Synthesis off (default): context-less traffic produces no spans.
func TestProcessEvent_NoSynthesize_ContextlessDropped(t *testing.T) {
	m := newTestManager(false)
	m.ProcessEvent(httpReq(4000, 1000, ""), nil)
	m.ProcessEvent(httpResp(4000, 5000, 4000), nil)

	if n := m.traceTracker.GetTraceCount(); n != 0 {
		t.Errorf("expected 0 traces without context and synthesis off, got %d", n)
	}
}
