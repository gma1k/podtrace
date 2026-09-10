package workloadmetrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/tracing"
)

const (
	testTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	testSpanID  = "00f067aa0ba902b7"
)

func tracedEvent(t events.EventType, latencyNS uint64) *events.Event {
	return &events.Event{
		Type:      t,
		CgroupID:  kernelTestCgroup,
		LatencyNS: latencyNS,
		Bytes:     512,
		Details:   "200",
		TraceID:   testTraceID,
		SpanID:    testSpanID,
	}
}

func TestAnEventWithATraceIDCarriesAnExemplar(t *testing.T) {
	labels, ok := exemplarFor(tracedEvent(events.EventHTTPResp, 1_000_000))
	if !ok {
		t.Fatal("a traced event produced no exemplar")
	}
	if labels[exemplarTraceIDLabel] != testTraceID {
		t.Errorf("trace_id = %q, want %q. Grafana's metrics-to-traces jump looks for this "+
			"label name specifically", labels[exemplarTraceIDLabel], testTraceID)
	}
	if labels[exemplarSpanIDLabel] != testSpanID {
		t.Errorf("span_id = %q, want %q", labels[exemplarSpanIDLabel], testSpanID)
	}
}

func TestAnEventWithoutATraceIDCarriesNoExemplar(t *testing.T) {
	for _, e := range []*events.Event{
		nil,
		{Type: events.EventHTTPResp},
		{Type: events.EventHTTPResp, SpanID: testSpanID},
	} {
		if _, ok := exemplarFor(e); ok {
			t.Errorf("event %+v produced an exemplar; without a trace id there is nothing to "+
				"link to, and a span id alone cannot address a trace", e)
		}
	}
}

func TestAnOversizedExemplarDegradesRatherThanBeingRejected(t *testing.T) {
	e := &events.Event{
		Type:    events.EventHTTPResp,
		TraceID: strings.Repeat("a", 100),
		SpanID:  strings.Repeat("b", 100),
	}
	labels, ok := exemplarFor(e)
	if !ok {
		t.Fatal("an oversized exemplar was dropped entirely; the trace id alone still fits")
	}
	if _, present := labels[exemplarSpanIDLabel]; present {
		t.Error("the span id survived past the budget; the pair would be rejected at scrape time")
	}
	if got := exemplarLabelLen(labels); got > exemplarLabelBudget {
		t.Errorf("exemplar is %d chars, over the %d budget", got, exemplarLabelBudget)
	}

	huge := &events.Event{Type: events.EventHTTPResp, TraceID: strings.Repeat("c", 200)}
	if _, ok := exemplarFor(huge); ok {
		t.Error("an exemplar that cannot fit at all was still produced")
	}
}

func exemplarSink(t *testing.T) (*Sink, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{
		Lookup: kernelTestLookup,
		ResolvePeer: func(ip string, port uint16) (PeerIdentity, bool) {
			return PeerIdentity{Service: "payments", Namespace: "shop"}, true
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return sink, reg
}

func exemplarsOn(t *testing.T, reg *prometheus.Registry, name string) []string {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	var out []string
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			if c := m.GetCounter(); c != nil && c.GetExemplar() != nil {
				for _, l := range c.GetExemplar().GetLabel() {
					if l.GetName() == exemplarTraceIDLabel {
						out = append(out, l.GetValue())
					}
				}
			}
			for _, b := range m.GetHistogram().GetBucket() {
				if b.GetExemplar() == nil {
					continue
				}
				for _, l := range b.GetExemplar().GetLabel() {
					if l.GetName() == exemplarTraceIDLabel {
						out = append(out, l.GetValue())
					}
				}
			}
		}
	}
	return out
}

func TestL7MetricsExposeTheTraceIDOnTheWire(t *testing.T) {
	sink, reg := exemplarSink(t)

	if err := sink.Export(t.Context(), []*events.Event{
		tracedEvent(events.EventHTTPResp, 3_000_000),
	}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	for _, family := range []string{
		"podtrace_workload_l7_requests_total",
		"podtrace_workload_l7_request_duration_seconds",
	} {
		got := exemplarsOn(t, reg, family)
		if len(got) == 0 {
			t.Errorf("%s carries no exemplar; the p99 spike is not clickable into the trace "+
				"that caused it, which is the whole handoff between the two planes", family)
			continue
		}
		if got[0] != testTraceID {
			t.Errorf("%s exemplar trace_id = %q, want %q", family, got[0], testTraceID)
		}
	}
}

func TestTheServiceMapEdgeCarriesTheTraceIDToo(t *testing.T) {
	sink, reg := exemplarSink(t)

	e := tracedEvent(events.EventHTTPResp, 5_000_000)
	e.PeerDstIP = "10.244.1.7"
	e.PeerDstPort = 8080
	if err := sink.Export(t.Context(), []*events.Event{e}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	got := exemplarsOn(t, reg, "podtrace_workload_edge_requests_total")
	if len(got) == 0 || got[0] != testTraceID {
		t.Errorf("edge exemplars = %v, want %q. The map is where an operator starts, so a slow "+
			"dependency there has to be clickable into the trace, not just into a name",
			got, testTraceID)
	}
}

func TestUntracedTrafficStillRecordsWithoutAnExemplar(t *testing.T) {
	sink, reg := exemplarSink(t)

	if err := sink.Export(t.Context(), []*events.Event{
		{Type: events.EventHTTPResp, CgroupID: kernelTestCgroup, LatencyNS: 2_000_000, Details: "200"},
	}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	if got := len(gather(t, reg, "podtrace_workload_l7_requests_total")); got == 0 {
		t.Error("untraced traffic produced no metric at all; most requests carry no traceparent " +
			"and they must still be counted")
	}
	if got := exemplarsOn(t, reg, "podtrace_workload_l7_requests_total"); len(got) != 0 {
		t.Errorf("untraced traffic produced exemplars %v; there is no trace to point at", got)
	}
}

func TestObserveAndAddFallBackWhenExemplarsAreUnsupported(t *testing.T) {
	observeExemplar(plainObserver{}, 1.5, prometheus.Labels{"trace_id": "x"})
	addExemplar(plainCounter{}, 1, prometheus.Labels{"trace_id": "x"})
	observeExemplar(plainObserver{}, 1.5, nil)
	addExemplar(plainCounter{}, 1, nil)
}

type plainObserver struct{}

func (plainObserver) Observe(float64) {}

type plainCounter struct{ prometheus.Counter }

func (plainCounter) Add(float64) {}
func (plainCounter) Inc()        {}

func TestTheSinkEnrichesTraceContextItselfLikeTheAgentDoes(t *testing.T) {
	reg := prometheus.NewRegistry()
	enrich := tracing.NewContextEnricher().Enrich
	sink, err := New(reg, Options{
		Lookup:       kernelTestLookup,
		TraceContext: enrich,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const correlation = uint64(918273645)
	traceparent := "traceparent: 00-" + testTraceID + "-" + testSpanID + "-01"

	batch := []*events.Event{
		{
			Type:          events.EventHTTPReq,
			CgroupID:      kernelTestCgroup,
			CorrelationID: correlation,
			Details:       traceparent,
		},
		{
			Type:          events.EventHTTPResp,
			CgroupID:      kernelTestCgroup,
			CorrelationID: correlation,
			LatencyNS:     4_000_000,
			Details:       "200",
		},
	}
	if err := sink.Export(t.Context(), batch); err != nil {
		t.Fatalf("Export: %v", err)
	}

	got := exemplarsOn(t, reg, "podtrace_workload_l7_requests_total")
	if len(got) == 0 {
		t.Fatalf("no exemplar after the sink enriched the batch itself.\n\nThe response " +
			"event arrives with only a status code in Details; its trace id comes from " +
			"joining it to the request. If that join is not wired into the sink, the " +
			"metric-to-trace link is silently absent on every node.")
	}
	if got[0] != testTraceID {
		t.Errorf("exemplar trace_id = %q, want %q from the request's traceparent",
			got[0], testTraceID)
	}
}

func TestUntracedTrafficStillNeedsNoEnrichment(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{
		Lookup:       kernelTestLookup,
		TraceContext: tracing.NewContextEnricher().Enrich,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := sink.Export(t.Context(), []*events.Event{{
		Type: events.EventHTTPResp, CgroupID: kernelTestCgroup,
		CorrelationID: 42, LatencyNS: 1_000_000, Details: "200",
	}}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	if len(gather(t, reg, "podtrace_workload_l7_requests_total")) == 0 {
		t.Error("untraced traffic was not counted")
	}
	if got := exemplarsOn(t, reg, "podtrace_workload_l7_requests_total"); len(got) != 0 {
		t.Errorf("an exemplar %v was minted for traffic with no trace context", got)
	}
}
