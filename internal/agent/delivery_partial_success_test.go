package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/gma1k/podtrace/pkg/exporter/bundle"
)

func partialSuccessCollector(t *testing.T, rejected *atomic.Int64) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body, _ := proto.Marshal(&coltracepb.ExportTraceServiceResponse{
			PartialSuccess: &coltracepb.ExportTracePartialSuccess{RejectedSpans: rejected.Load(), ErrorMessage: "span too large"},
		})
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func readOnlySpans(n int) []sdktrace.ReadOnlySpan {
	out := make([]sdktrace.ReadOnlySpan, n)
	for i := range out {
		out[i] = tracetest.SpanStub{
			Name: "op",
			SpanContext: trace.NewSpanContext(trace.SpanContextConfig{
				TraceID: trace.TraceID{1},
				SpanID:  trace.SpanID{byte(i + 1)},
			}),
		}.Snapshot()
	}
	return out
}

func TestAPartialSuccessIsDeliveredAndCountsOnlyTheRejectedSpansAsDropped(t *testing.T) {
	var rejected atomic.Int64
	rejected.Store(2)
	inner, err := newOTLPSpanExporter(&BundlePayload{
		Type: bundle.TypeOTLP, Endpoint: partialSuccessCollector(t, &rejected), Insecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	m := NewMetrics()
	h := newDeliveryHealth()
	e := &deliveryObservingExporter{inner: inner, cr: deliveryCR, name: "otlp", metrics: m, delivery: h}
	h.register(deliveryCR, e)
	t.Cleanup(func() { _ = e.Shutdown(context.Background()) })

	if err := e.ExportSpans(context.Background(), readOnlySpans(5)); err != nil {
		t.Fatalf("a partial success must not fail the batch: %v", err)
	}

	if _, failing := h.failing(deliveryCR); failing {
		t.Fatal("a partial success marked the PodTrace's delivery as failing")
	}
	labels := prometheus.Labels{"cr_namespace": deliveryCR.Namespace, "cr_name": deliveryCR.Name}
	if got := counterValue(t, m.SpansDelivered, labels); got != 3 {
		t.Fatalf("spans_delivered_total = %v, want 3", got)
	}
	labels["reason"] = ExporterErrRejected
	if got := counterValue(t, m.ExportDeliveryDropped, labels); got != 2 {
		t.Fatalf("export_delivery_dropped_total{reason=rejected} = %v, want 2", got)
	}

	rejected.Store(9)
	if err := e.ExportSpans(context.Background(), readOnlySpans(4)); err != nil {
		t.Fatal(err)
	}
	if got := counterValue(t, m.ExportDeliveryDropped, labels); got != 6 {
		t.Fatalf("export_delivery_dropped_total{reason=rejected} = %v, want 6 (a count above the batch is clamped)", got)
	}

	rejected.Store(0)
	if err := e.ExportSpans(context.Background(), readOnlySpans(1)); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	stillRejecting := e.rejecting
	e.mu.Unlock()
	if stillRejecting {
		t.Fatal("a batch with no rejected span must end the rejection episode")
	}
}

func TestClassifyExporterErrorNamesARejection(t *testing.T) {
	var rejected atomic.Int64
	rejected.Store(1)
	inner, err := newOTLPSpanExporter(&BundlePayload{
		Type: bundle.TypeOTLP, Endpoint: partialSuccessCollector(t, &rejected), Insecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inner.Shutdown(context.Background()) })
	exportErr := inner.ExportSpans(context.Background(), readOnlySpans(1))
	if exportErr == nil {
		t.Fatal("the OTLP exporter no longer reports a partial success as an error")
	}
	if got := ClassifyExporterError(exportErr); got != ExporterErrRejected {
		t.Fatalf("ClassifyExporterError = %q, want %q", got, ExporterErrRejected)
	}
	if got := ClassifyExporterError(errors.Join(exportErr, errors.New("missing token"))); got == ExporterErrRejected {
		t.Fatal("a rejection mixed with a real failure must not be classified as a rejection")
	}
}
