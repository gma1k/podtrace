package tracing

import (
	"testing"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
)

const (
	enricherTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	enricherSpanID  = "00f067aa0ba902b7"
	enricherHeader  = "traceparent: 00-" + enricherTraceID + "-" + enricherSpanID + "-01"
)

func TestARequestHeaderYieldsTraceContext(t *testing.T) {
	e := &events.Event{Type: events.EventHTTPReq, CorrelationID: 7, Details: enricherHeader}

	if !NewContextEnricher().Enrich(e) {
		t.Fatalf("the BPF-produced details string was not recognised:\n%q", enricherHeader)
	}
	if e.TraceID != enricherTraceID {
		t.Errorf("TraceID = %q, want %q", e.TraceID, enricherTraceID)
	}
	if e.ParentSpanID != enricherSpanID {
		t.Errorf("ParentSpanID = %q, want the header's span id %q", e.ParentSpanID, enricherSpanID)
	}
	if e.SpanID == "" {
		t.Error("no span id was derived; an exemplar's span_id would be empty")
	}
}

func TestAResponseIsJoinedBackToItsRequest(t *testing.T) {
	enricher := NewContextEnricher()
	const correlation = uint64(4242)

	req := &events.Event{Type: events.EventHTTPReq, CorrelationID: correlation, Details: enricherHeader}
	if !enricher.Enrich(req) {
		t.Fatal("request not enriched")
	}

	resp := &events.Event{Type: events.EventHTTPResp, CorrelationID: correlation, Details: "200"}
	if !enricher.Enrich(resp) {
		t.Fatal("the response was not joined back to its request")
	}
	if resp.TraceID != enricherTraceID {
		t.Errorf("resp.TraceID = %q, want %q", resp.TraceID, enricherTraceID)
	}
	if resp.SpanID != req.SpanID {
		t.Errorf("resp.SpanID = %q, req.SpanID = %q; the pair must share a span so the "+
			"metric and the trace agree on which request they describe", resp.SpanID, req.SpanID)
	}
}

func TestTheJoinIsConsumedSoAReplayCannotReuseIt(t *testing.T) {
	enricher := NewContextEnricher()
	const correlation = uint64(99)

	enricher.Enrich(&events.Event{Type: events.EventHTTPReq, CorrelationID: correlation, Details: enricherHeader})
	first := &events.Event{Type: events.EventHTTPResp, CorrelationID: correlation, Details: "200"}
	if !enricher.Enrich(first) {
		t.Fatal("first response not joined")
	}

	second := &events.Event{Type: events.EventHTTPResp, CorrelationID: correlation, Details: "200"}
	if enricher.Enrich(second) {
		t.Errorf("a second response reused the consumed context and got TraceID %q",
			second.TraceID)
	}
}

func TestTrafficWithNoContextGetsNoInventedTraceID(t *testing.T) {
	original := config.SynthesizeSpans
	config.SynthesizeSpans = false
	t.Cleanup(func() { config.SynthesizeSpans = original })

	e := &events.Event{Type: events.EventHTTPResp, CorrelationID: 5, Details: "200"}
	if NewContextEnricher().Enrich(e) {
		t.Errorf("a trace id %q was minted for traffic that carried no context", e.TraceID)
	}
	if e.TraceID != "" {
		t.Errorf("TraceID = %q, want empty", e.TraceID)
	}
}

func TestSynthesisMintsATraceWhenExplicitlyEnabled(t *testing.T) {
	original := config.SynthesizeSpans
	config.SynthesizeSpans = true
	t.Cleanup(func() { config.SynthesizeSpans = original })

	e := &events.Event{Type: events.EventHTTPResp, CorrelationID: 5, Details: "200"}
	if !NewContextEnricher().Enrich(e) {
		t.Fatal("synthesis was enabled but no context was assigned")
	}
	if e.TraceID == "" || e.SpanID == "" {
		t.Errorf("synthesised context incomplete: trace=%q span=%q", e.TraceID, e.SpanID)
	}
}

func TestASynthesisedTraceIsStableForTheSameRequest(t *testing.T) {
	original := config.SynthesizeSpans
	config.SynthesizeSpans = true
	t.Cleanup(func() { config.SynthesizeSpans = original })

	enricher := NewContextEnricher()
	a := &events.Event{Type: events.EventHTTPResp, CorrelationID: 31337, Details: "200"}
	b := &events.Event{Type: events.EventHTTPResp, CorrelationID: 31337, Details: "200"}
	enricher.Enrich(a)
	enricher.Enrich(b)

	if a.TraceID != b.TraceID {
		t.Errorf("same correlation id produced different traces: %q vs %q", a.TraceID, b.TraceID)
	}
}

func TestNonL7EventsCarryHeaderContextButAreNotJoined(t *testing.T) {
	e := &events.Event{Type: events.EventDNS, Details: enricherHeader}
	if !NewContextEnricher().Enrich(e) {
		t.Fatal("a non-L7 event with a header was not enriched")
	}
	if e.TraceID != enricherTraceID {
		t.Errorf("TraceID = %q", e.TraceID)
	}
}

func TestAnL7EventWithoutACorrelationIDIsNotJoinable(t *testing.T) {
	enricher := NewContextEnricher()
	enricher.Enrich(&events.Event{Type: events.EventHTTPReq, CorrelationID: 0, Details: enricherHeader})

	resp := &events.Event{Type: events.EventHTTPResp, CorrelationID: 0, Details: "200"}
	if enricher.Enrich(resp) {
		t.Errorf("a response with no correlation id was joined anyway, TraceID=%q", resp.TraceID)
	}
}

func TestEnrichIsSafeOnNilInputs(t *testing.T) {
	var nilEnricher *ContextEnricher
	if nilEnricher.Enrich(&events.Event{}) {
		t.Error("a nil enricher reported success")
	}
	if NewContextEnricher().Enrich(nil) {
		t.Error("a nil event reported success")
	}
}

func TestAnUnparseableHeaderIsIgnoredRatherThanFatal(t *testing.T) {
	for _, details := range []string{
		"",
		"200",
		"traceparent: garbage",
		"traceparent: 00-tooshort-x-01",
		"traceparent: 99-" + enricherTraceID + "-" + enricherSpanID + "-01",
		"traceparent: 00-00000000000000000000000000000000-" + enricherSpanID + "-01",
	} {
		e := &events.Event{Type: events.EventHTTPResp, CorrelationID: 1, Details: details}
		NewContextEnricher().Enrich(e)
		if e.TraceID != "" && e.TraceID != enricherTraceID {
			t.Errorf("details %q produced TraceID %q", details, e.TraceID)
		}
	}
}
