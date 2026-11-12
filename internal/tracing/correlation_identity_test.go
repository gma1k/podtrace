package tracing

import (
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
)

func TestCorrelationKeyIsScopedToTheCgroup(t *testing.T) {
	a := &events.Event{Type: events.EventHTTPReq, CgroupID: 1, CorrelationID: 500}
	b := &events.Event{Type: events.EventHTTPReq, CgroupID: 2, CorrelationID: 500}
	resp := &events.Event{Type: events.EventHTTPResp, CgroupID: 1, CorrelationID: 500, PID: 99}

	if correlationKey(a) == correlationKey(b) {
		t.Fatal("requests of two containers that started in the same nanosecond share a correlation key")
	}
	if correlationKey(a) != correlationKey(resp) {
		t.Fatal("a response must share its request's key even when another thread wrote it")
	}
}

func TestDerivedIDsAreStableWithinAProcessButNotAcrossProcesses(t *testing.T) {
	saved := idSalt
	t.Cleanup(func() { idSalt = saved })

	key := "1:500"
	traceID, spanID := deriveTraceID(key), deriveSpanID(key)
	if deriveTraceID(key) != traceID || deriveSpanID(key) != spanID {
		t.Fatal("ids derived for one key changed within the process")
	}
	if len(traceID) != 32 || len(spanID) != 16 {
		t.Fatalf("derived ids have the wrong width: trace %q span %q", traceID, spanID)
	}

	idSalt = newIDSalt()
	if deriveTraceID(key) == traceID {
		t.Error("another node deriving a trace id for the same monotonic start time collides with this one")
	}
	if deriveSpanID(key) == spanID {
		t.Error("another node deriving a span id for the same monotonic start time collides with this one")
	}
}

func TestNewIDSaltIsRandom(t *testing.T) {
	if a, b := newIDSalt(), newIDSalt(); a == b || len(a) != 16 {
		t.Fatalf("salts %x and %x are not distinct 16-byte values", a, b)
	}
}

func TestAResponseFromAnotherContainerDoesNotTakeTheRequestContext(t *testing.T) {
	enricher := NewContextEnricher()
	const correlation = uint64(4242)

	if !enricher.Enrich(&events.Event{Type: events.EventHTTPReq, CgroupID: 1, CorrelationID: correlation, Details: enricherHeader}) {
		t.Fatal("request not enriched")
	}
	other := &events.Event{Type: events.EventHTTPResp, CgroupID: 2, CorrelationID: correlation, Details: "200"}
	if enricher.Enrich(other) {
		t.Fatalf("a response of another container joined the request's trace %s", other.TraceID)
	}
	own := &events.Event{Type: events.EventHTTPResp, CgroupID: 1, CorrelationID: correlation, Details: "200"}
	if !enricher.Enrich(own) || own.TraceID != enricherTraceID {
		t.Fatal("the request's own response lost its trace context")
	}
}

func TestSynthesisedTracesOfTwoContainersStayApart(t *testing.T) {
	saved := config.SynthesizeSpans
	t.Cleanup(func() { config.SynthesizeSpans = saved })
	config.SynthesizeSpans = true
	enricher := NewContextEnricher()

	a := &events.Event{Type: events.EventHTTPReq, CgroupID: 1, CorrelationID: 77}
	b := &events.Event{Type: events.EventHTTPReq, CgroupID: 2, CorrelationID: 77}
	enricher.Enrich(a)
	enricher.Enrich(b)
	if a.TraceID == "" || a.TraceID == b.TraceID || a.SpanID == b.SpanID {
		t.Fatalf("unrelated requests merged: a=%s/%s b=%s/%s", a.TraceID, a.SpanID, b.TraceID, b.SpanID)
	}
}

func ageAllEntries(c *correlationCache, by time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for el := c.order.Front(); el != nil; el = el.Next() {
		el.Value.(*correlationItem).entry.storedNS -= int64(by)
	}
}

func TestTheEnricherDropsAbandonedRequestsWithoutATimer(t *testing.T) {
	enricher := NewContextEnricher()
	enricher.Enrich(&events.Event{Type: events.EventHTTPReq, CgroupID: 1, CorrelationID: 1, Details: enricherHeader})
	enricher.Enrich(&events.Event{Type: events.EventHTTPReq, CgroupID: 1, CorrelationID: 2, Details: enricherHeader})
	ageAllEntries(enricher.corr, correlationMaxAge+time.Second)

	enricher.Enrich(&events.Event{Type: events.EventHTTPReq, CgroupID: 1, CorrelationID: 3, Details: enricherHeader})

	if got := len(enricher.corr.m); got != 1 {
		t.Fatalf("cache holds %d entries, want only the fresh request: abandoned requests were kept", got)
	}
	if _, ok := enricher.corr.loadDelete(correlationKey(&events.Event{CgroupID: 1, CorrelationID: 3})); !ok {
		t.Fatal("the fresh request was dropped")
	}
}

func TestStoreKeepsEntriesYoungerThanTheMaxAge(t *testing.T) {
	c := newCorrelationCache(16)
	c.store("pending", correlationEntry{traceID: "t"})
	ageAllEntries(c, correlationMaxAge-time.Second)

	c.store("next", correlationEntry{traceID: "t"})

	if _, ok := c.loadDelete("pending"); !ok {
		t.Fatal("a request still within the max age lost its context")
	}
}
