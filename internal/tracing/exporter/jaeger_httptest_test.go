package exporter

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/diagnose/tracker"
)

func newTestTrace() *tracker.Trace {
	return &tracker.Trace{
		TraceID: "trace-httptest",
		Spans: []*tracker.Span{
			{
				TraceID:   "trace-httptest",
				SpanID:    "span-httptest",
				Operation: "test-op",
				Service:   "test-service",
				StartTime: time.Now(),
				Duration:  10 * time.Millisecond,
			},
		},
	}
}

// TestJaegerExporter_exportTrace_HTTPSuccess covers the defer+return-nil path
// (lines 172-174 and 180) when the server returns 200 OK.
func TestJaegerExporter_exportTrace_HTTPSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	exporter, err := NewJaegerExporter(srv.URL, 1.0)
	if err != nil {
		t.Fatalf("NewJaegerExporter() error: %v", err)
	}

	err = exporter.exportTrace(newTestTrace())
	if err != nil {
		t.Errorf("exportTrace() unexpected error: %v", err)
	}
}

// TestJaegerExporter_exportTrace_HTTPAccepted covers the 202 Accepted success path.
func TestJaegerExporter_exportTrace_HTTPAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)

	exporter, err := NewJaegerExporter(srv.URL, 1.0)
	if err != nil {
		t.Fatalf("NewJaegerExporter() error: %v", err)
	}

	err = exporter.exportTrace(newTestTrace())
	if err != nil {
		t.Errorf("exportTrace() unexpected error for 202: %v", err)
	}
}

// TestJaegerExporter_exportTrace_HTTPError covers the non-200/202 status error path
// (lines 176-178) when the server returns 400 Bad Request.
func TestJaegerExporter_exportTrace_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)

	exporter, err := NewJaegerExporter(srv.URL, 1.0)
	if err != nil {
		t.Fatalf("NewJaegerExporter() error: %v", err)
	}

	err = exporter.exportTrace(newTestTrace())
	if err == nil {
		t.Error("expected error for 400 Bad Request, got nil")
	}
}

// TestJaegerExporter_ExportTraces_WithServer covers ExportTraces with a live
// server — exercises the full exportTrace success path via ExportTraces.
func TestJaegerExporter_ExportTraces_WithServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	exporter, err := NewJaegerExporter(srv.URL, 1.0)
	if err != nil {
		t.Fatalf("NewJaegerExporter() error: %v", err)
	}

	err = exporter.ExportTraces([]*tracker.Trace{newTestTrace()})
	if err != nil {
		t.Errorf("ExportTraces() unexpected error: %v", err)
	}
}
