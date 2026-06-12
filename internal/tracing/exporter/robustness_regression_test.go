package exporter

import (
	"fmt"
	"testing"

	"go.opentelemetry.io/otel/trace"

	"github.com/podtrace/podtrace/internal/diagnose/tracker"
	"github.com/podtrace/podtrace/internal/events"
)

// TestSampleTrace_RateIsRespected: the old time.Now()%int64(1/rate) check
// truncated every rate in (0.5, 1.0) to "always export" and re-rolled the
// decision on each export tick. The hash-based sampler must export a
// fraction of trace IDs close to the configured rate.
func TestSampleTrace_RateIsRespected(t *testing.T) {
	for _, rate := range []float64{0.1, 0.5, 0.7, 0.9} {
		sampled := 0
		const n = 20000
		for i := 0; i < n; i++ {
			if sampleTrace(fmt.Sprintf("trace-%d", i), rate) {
				sampled++
			}
		}
		got := float64(sampled) / n
		if got < rate-0.02 || got > rate+0.02 {
			t.Errorf("rate %.1f: sampled fraction %.3f, want within ±0.02", rate, got)
		}
	}
}

// TestSampleTrace_DeterministicPerTrace: one trace gets ONE verdict — the
// clock-based roll exported every long-lived trace eventually because the
// decision repeated on each 5s tick.
func TestSampleTrace_DeterministicPerTrace(t *testing.T) {
	for i := 0; i < 100; i++ {
		id := fmt.Sprintf("trace-%d", i)
		first := sampleTrace(id, 0.5)
		for roll := 0; roll < 20; roll++ {
			if sampleTrace(id, 0.5) != first {
				t.Fatalf("trace %s changed sampling verdict between rolls", id)
			}
		}
	}
	if sampleTrace("any", 1.0) != true || sampleTrace("any", 0.0) != false {
		t.Error("boundary rates must be all-or-nothing")
	}
}

// TestOTLPSpanSnapshot_PreservesSpanIdentity: replaying spans through the
// SDK tracer minted fresh span IDs and demoted the original ID to the
// parent — every OTLP backend showed phantom intermediate spans. The
// exported snapshot must carry the original IDs verbatim.
func TestOTLPSpanSnapshot_PreservesSpanIdentity(t *testing.T) {
	exporter, err := NewOTLPExporter("http://localhost:4318", 1.0)
	if err != nil {
		t.Fatalf("NewOTLPExporter: %v", err)
	}
	t.Cleanup(func() { _ = exporter.Shutdown(t.Context()) })

	span := errorSurfaceTrace()[0].Spans[0]
	span.ParentSpanID = "fedcba9876543210"

	snapshot, err := exporter.spanSnapshot(span)
	if err != nil {
		t.Fatalf("spanSnapshot: %v", err)
	}

	wantTrace, _ := trace.TraceIDFromHex(span.TraceID)
	wantSpan, _ := trace.SpanIDFromHex(span.SpanID)
	wantParent, _ := trace.SpanIDFromHex(span.ParentSpanID)

	if snapshot.SpanContext().TraceID() != wantTrace {
		t.Errorf("trace ID = %s, want %s", snapshot.SpanContext().TraceID(), span.TraceID)
	}
	if snapshot.SpanContext().SpanID() != wantSpan {
		t.Errorf("span ID = %s, want the ORIGINAL %s", snapshot.SpanContext().SpanID(), span.SpanID)
	}
	if snapshot.Parent().SpanID() != wantParent {
		t.Errorf("parent span ID = %s, want %s", snapshot.Parent().SpanID(), span.ParentSpanID)
	}
}

// TestSpanTypeAndZipkinKind_CacheEvents: TypeString returns "CACHE" for
// Redis/Memcached events; the comparisons against "Redis"/"Memcached"
// were dead branches, so cache spans fell through to "custom"/no kind.
func TestSpanTypeAndZipkinKind_CacheEvents(t *testing.T) {
	span := &tracker.Span{Events: []*events.Event{{Type: events.EventRedisCmd}}}

	if got := spanType(span); got != "cache" {
		t.Errorf("spanType = %q, want cache", got)
	}
	if got := zipkinKind(span); got != "CLIENT" {
		t.Errorf("zipkinKind = %q, want CLIENT", got)
	}
}
