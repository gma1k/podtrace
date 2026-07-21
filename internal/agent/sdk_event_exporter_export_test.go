package agent

import (
	"context"
	"sync"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/tracing/extractor"
	"github.com/podtrace/podtrace/pkg/exporter/bundle"
)

const (
	testTraceIDHex = "4bf92f3577b34da6a3ce929d0e0e4736"
	testSpanIDHex  = "00f067aa0ba902b7"
)

type recordingSpanExporter struct {
	mu    sync.Mutex
	spans []sdktrace.ReadOnlySpan
}

func (r *recordingSpanExporter) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.spans = append(r.spans, spans...)
	return nil
}
func (r *recordingSpanExporter) Shutdown(context.Context) error { return nil }

func (r *recordingSpanExporter) snapshot() []sdktrace.ReadOnlySpan {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]sdktrace.ReadOnlySpan, len(r.spans))
	copy(out, r.spans)
	return out
}

func spanAttrSet(s sdktrace.ReadOnlySpan) map[string]string {
	out := map[string]string{}
	for _, kv := range s.Attributes() {
		out[string(kv.Key)] = kv.Value.String()
	}
	return out
}

func TestSDKEventExporter_Export_StampsProtocolAndNetworkAttributes(t *testing.T) {
	rec := &recordingSpanExporter{}
	b := &bundle.Payload{Type: bundle.TypeOTLP, Endpoint: "x:4318", Insecure: true}
	exp, err := newSDKEventExporter("otlp", CRKey{"ns", "cr"}, b, rec)
	if err != nil {
		t.Fatalf("newSDKEventExporter: %v", err)
	}

	now := uint64(time.Now().UnixNano())
	batch := []*events.Event{
		{
			Type:        events.EventHTTPReq,
			Timestamp:   now,
			TCPState:    events.HTTPTransportH2TLS,
			PeerDstIP:   "10.0.0.5",
			PeerDstPort: 443,
			PeerSrcIP:   "10.0.0.9",
			PeerSrcPort: 55123,
			Target:      "example.com/api",
		},
		{Type: events.EventUSDT, Timestamp: now, Details: "myprobe:entry"},
		{Type: events.EventDNS, Timestamp: now, Details: "93.184.216.34"},
	}
	if err := exp.Export(context.Background(), batch); err != nil {
		t.Fatalf("Export: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := exp.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	spans := rec.snapshot()
	if len(spans) != 3 {
		t.Fatalf("captured %d spans, want 3", len(spans))
	}

	var httpAttrs, usdtAttrs, dnsAttrs map[string]string
	for _, s := range spans {
		attrs := spanAttrSet(s)
		switch {
		case attrs["http.scheme"] != "":
			httpAttrs = attrs
		case attrs["podtrace.usdt.probe"] != "":
			usdtAttrs = attrs
		case attrs["dns.resolved"] != "":
			dnsAttrs = attrs
		}
	}

	if httpAttrs == nil {
		t.Fatal("no http.req span captured")
	}
	if httpAttrs["http.scheme"] != "https" {
		t.Errorf("http.scheme = %q, want https", httpAttrs["http.scheme"])
	}
	if _, ok := httpAttrs["podtrace.http.transport"]; !ok {
		t.Error("missing podtrace.http.transport attribute")
	}
	if httpAttrs["network.peer.address"] != "10.0.0.5" {
		t.Errorf("network.peer.address = %q, want 10.0.0.5", httpAttrs["network.peer.address"])
	}
	if httpAttrs["network.local.address"] != "10.0.0.9" {
		t.Errorf("network.local.address = %q, want 10.0.0.9", httpAttrs["network.local.address"])
	}

	if usdtAttrs == nil || usdtAttrs["podtrace.usdt.probe"] != "myprobe:entry" {
		t.Errorf("usdt span missing probe attribute: %+v", usdtAttrs)
	}
	if dnsAttrs == nil || dnsAttrs["dns.resolved"] != "93.184.216.34" {
		t.Errorf("dns span missing dns.resolved attribute: %+v", dnsAttrs)
	}
}

func TestSDKEventExporter_Export_LinksRemoteParent(t *testing.T) {
	rec := &recordingSpanExporter{}
	b := &bundle.Payload{Type: bundle.TypeOTLP, Endpoint: "x:4318", Insecure: true}
	exp, err := newSDKEventExporter("otlp", CRKey{"ns", "cr"}, b, rec)
	if err != nil {
		t.Fatalf("newSDKEventExporter: %v", err)
	}

	ev := &events.Event{
		Type:         events.EventHTTPReq,
		Timestamp:    uint64(time.Now().UnixNano()),
		TraceID:      testTraceIDHex,
		ParentSpanID: testSpanIDHex,
		TraceFlags:   0x01,
	}
	if err := exp.Export(context.Background(), []*events.Event{ev}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := exp.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	spans := rec.snapshot()
	if len(spans) != 1 {
		t.Fatalf("captured %d spans, want 1", len(spans))
	}
	parent := spans[0].Parent()
	if parent.TraceID().String() != testTraceIDHex {
		t.Errorf("parent trace ID = %q, want %q", parent.TraceID().String(), testTraceIDHex)
	}
	if parent.SpanID().String() != testSpanIDHex {
		t.Errorf("parent span ID = %q, want %q", parent.SpanID().String(), testSpanIDHex)
	}
	if !parent.IsRemote() {
		t.Error("parent context should be flagged remote")
	}
}

func TestSDKEventExporter_RemoteParent_Direct(t *testing.T) {
	e := &sdkEventExporter{extractor: extractor.NewHTTPExtractor()}

	t.Run("ValidFromFields", func(t *testing.T) {
		sc, ok := e.remoteParent(&events.Event{TraceID: testTraceIDHex, ParentSpanID: testSpanIDHex, TraceFlags: 0x01})
		if !ok || !sc.IsValid() {
			t.Fatalf("expected valid remote parent, ok=%v valid=%v", ok, sc.IsValid())
		}
		if !sc.IsSampled() {
			t.Error("sampled flag should be set from TraceFlags 0x01")
		}
	})

	t.Run("FromRawHTTPHeaders", func(t *testing.T) {
		ev := &events.Event{
			Type:    events.EventHTTPReq,
			Details: "traceparent: 00-" + testTraceIDHex + "-" + testSpanIDHex + "-01",
		}
		sc, ok := e.remoteParent(ev)
		if !ok {
			t.Fatal("expected to extract remote parent from raw headers")
		}
		if sc.TraceID().String() != testTraceIDHex {
			t.Errorf("extracted trace ID = %q, want %q", sc.TraceID().String(), testTraceIDHex)
		}
	})

	t.Run("EmptyContextNoParent", func(t *testing.T) {
		if _, ok := e.remoteParent(&events.Event{Type: events.EventDNS}); ok {
			t.Error("event with no trace context must not yield a parent")
		}
	})

	t.Run("InvalidTraceIDHex", func(t *testing.T) {
		if _, ok := e.remoteParent(&events.Event{TraceID: "zzzz", ParentSpanID: testSpanIDHex}); ok {
			t.Error("invalid trace ID hex must be rejected")
		}
	})

	t.Run("InvalidSpanIDHex", func(t *testing.T) {
		if _, ok := e.remoteParent(&events.Event{TraceID: testTraceIDHex, ParentSpanID: "zzzz"}); ok {
			t.Error("invalid span ID hex must be rejected")
		}
	})
}

func TestSDKEventExporter_CloseNilTracerProvider(t *testing.T) {
	e := &sdkEventExporter{}
	if err := e.Close(context.Background()); err != nil {
		t.Errorf("Close with nil tp = %v, want nil", err)
	}
}

func TestDeliveryObservingExporter_RecoversAfterFailure(t *testing.T) {
	m := NewMetrics()
	cr := CRKey{Namespace: "ns", Name: "cr"}
	inner := &fakeSpanExporter{err: context.DeadlineExceeded}
	obs := &deliveryObservingExporter{inner: inner, cr: cr, name: "otlp", metrics: m}

	spans := make([]sdktrace.ReadOnlySpan, 2)
	if err := obs.ExportSpans(context.Background(), spans); err == nil {
		t.Fatal("first ExportSpans should propagate the inner failure")
	}

	inner.err = nil
	if err := obs.ExportSpans(context.Background(), spans); err != nil {
		t.Fatalf("second ExportSpans after recovery = %v, want nil", err)
	}

	obs.mu.Lock()
	stillFailing := obs.failing
	obs.mu.Unlock()
	if stillFailing {
		t.Error("failing flag should be cleared after a successful export")
	}
}
