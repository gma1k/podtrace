package exporter

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/diagnose/tracker"
)

func newTestTrace() *tracker.Trace {
	return &tracker.Trace{
		TraceID: "0123456789abcdef0123456789abcdef",
		Spans: []*tracker.Span{
			{
				TraceID:   "0123456789abcdef0123456789abcdef",
				SpanID:    "0123456789abcdef",
				Operation: "test-op",
				Service:   "test-service",
				StartTime: time.Now(),
				Duration:  10 * time.Millisecond,
			},
		},
	}
}

// TestJaegerExporter_ShipsOTLPToCollector is a regression test: the old
// exporter POSTed a homegrown JSON shape that no Jaeger collector release
// ingests (the legacy /api/traces endpoint speaks Thrift). The exporter
// must hit the OTLP path with a protobuf payload — what real Jaeger
// actually accepts.
func TestJaegerExporter_ShipsOTLPToCollector(t *testing.T) {
	var mu sync.Mutex
	var gotPath, gotContentType string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotPath, gotContentType, gotBody = r.URL.Path, r.Header.Get("Content-Type"), body
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	exporter, err := NewJaegerExporter(srv.URL, 1.0)
	if err != nil {
		t.Fatalf("NewJaegerExporter() error: %v", err)
	}
	t.Cleanup(func() { _ = exporter.Shutdown(t.Context()) })

	if err := exporter.ExportTraces([]*tracker.Trace{newTestTrace()}); err != nil {
		t.Fatalf("ExportTraces() error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotPath != "/v1/traces" {
		t.Errorf("POST path = %q, want the OTLP /v1/traces endpoint", gotPath)
	}
	if !strings.Contains(gotContentType, "protobuf") {
		t.Errorf("Content-Type = %q, want an OTLP protobuf payload", gotContentType)
	}
	if len(gotBody) == 0 {
		t.Error("empty body posted to the collector")
	}
}

// TestJaegerExporter_SurfacesCollectorRejection: a permanent 4xx from the
// collector must surface as an error, not be swallowed.
func TestJaegerExporter_SurfacesCollectorRejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)

	exporter, err := NewJaegerExporter(srv.URL, 1.0)
	if err != nil {
		t.Fatalf("NewJaegerExporter() error: %v", err)
	}
	t.Cleanup(func() { _ = exporter.Shutdown(t.Context()) })

	if err := exporter.ExportTraces([]*tracker.Trace{newTestTrace()}); err == nil {
		t.Error("expected an error for a 400 from the collector, got nil")
	}
}
