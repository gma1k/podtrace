package exporter

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/diagnose/tracker"
)

func newTestZipkinTrace() *tracker.Trace {
	return &tracker.Trace{
		TraceID: "aabbccddeeff00112233445566778899",
		Spans: []*tracker.Span{
			{
				TraceID:   "aabbccddeeff00112233445566778899",
				SpanID:    "1122334455667788",
				Operation: "test-op",
				Service:   "test-service",
				StartTime: time.Now(),
				Duration:  10 * time.Millisecond,
			},
		},
	}
}

func TestZipkinExporter_exportTrace_HTTPSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	exporter, err := NewZipkinExporter(srv.URL, 1.0)
	if err != nil {
		t.Fatalf("NewZipkinExporter() error: %v", err)
	}

	err = exporter.exportTrace(newTestZipkinTrace())
	if err != nil {
		t.Errorf("exportTrace() unexpected error: %v", err)
	}
}

func TestZipkinExporter_exportTrace_HTTPAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)

	exporter, err := NewZipkinExporter(srv.URL, 1.0)
	if err != nil {
		t.Fatalf("NewZipkinExporter() error: %v", err)
	}

	err = exporter.exportTrace(newTestZipkinTrace())
	if err != nil {
		t.Errorf("exportTrace() unexpected error for 202: %v", err)
	}
}

func TestZipkinExporter_exportTrace_HTTPNoContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	exporter, err := NewZipkinExporter(srv.URL, 1.0)
	if err != nil {
		t.Fatalf("NewZipkinExporter() error: %v", err)
	}

	err = exporter.exportTrace(newTestZipkinTrace())
	if err != nil {
		t.Errorf("exportTrace() unexpected error for 204: %v", err)
	}
}

func TestZipkinExporter_exportTrace_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)

	exporter, err := NewZipkinExporter(srv.URL, 1.0)
	if err != nil {
		t.Fatalf("NewZipkinExporter() error: %v", err)
	}

	err = exporter.exportTrace(newTestZipkinTrace())
	if err == nil {
		t.Error("expected error for 400 Bad Request, got nil")
	}
}

func TestZipkinExporter_ExportTraces_WithServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)

	exporter, err := NewZipkinExporter(srv.URL, 1.0)
	if err != nil {
		t.Fatalf("NewZipkinExporter() error: %v", err)
	}

	err = exporter.ExportTraces([]*tracker.Trace{newTestZipkinTrace()})
	if err != nil {
		t.Errorf("ExportTraces() unexpected error: %v", err)
	}
}

func TestZipkinExporter_exportTrace_PayloadFormat(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)

	exporter, err := NewZipkinExporter(srv.URL, 1.0)
	if err != nil {
		t.Fatalf("NewZipkinExporter() error: %v", err)
	}

	err = exporter.exportTrace(newTestZipkinTrace())
	if err != nil {
		t.Fatalf("exportTrace() unexpected error: %v", err)
	}

	// Payload must be a flat array of spans (Zipkin v2).
	var payload []zipkinSpan
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}
	if len(payload) != 1 {
		t.Errorf("expected 1 span in payload, got %d", len(payload))
	}
	span := payload[0]
	if span.LocalEndpoint.ServiceName != "test-service" {
		t.Errorf("expected serviceName 'test-service', got '%s'", span.LocalEndpoint.ServiceName)
	}
	if span.Name != "test-op" {
		t.Errorf("expected name 'test-op', got '%s'", span.Name)
	}
	if span.TraceID != "aabbccddeeff00112233445566778899" {
		t.Errorf("expected traceId 'aabbccddeeff00112233445566778899', got '%s'", span.TraceID)
	}
}

func TestZipkinExporter_exportTrace_ErrorTagInPayload(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)

	exporter, err := NewZipkinExporter(srv.URL, 1.0)
	if err != nil {
		t.Fatalf("NewZipkinExporter() error: %v", err)
	}

	trace := &tracker.Trace{
		TraceID: "aabbccddeeff00112233445566778899",
		Spans: []*tracker.Span{
			{
				TraceID:   "aabbccddeeff00112233445566778899",
				SpanID:    "1122334455667788",
				Operation: "error-op",
				Service:   "svc",
				StartTime: time.Now(),
				Duration:  10 * time.Millisecond,
				Error:     true,
			},
		},
	}

	err = exporter.exportTrace(trace)
	if err != nil {
		t.Fatalf("exportTrace() unexpected error: %v", err)
	}

	var payload []zipkinSpan
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}
	if payload[0].Tags["error"] != "true" {
		t.Errorf("expected tags[error]='true', got '%s'", payload[0].Tags["error"])
	}
}

func TestZipkinExporter_exportTrace_ContentTypeHeader(t *testing.T) {
	var contentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)

	exporter, err := NewZipkinExporter(srv.URL, 1.0)
	if err != nil {
		t.Fatalf("NewZipkinExporter() error: %v", err)
	}

	err = exporter.exportTrace(newTestZipkinTrace())
	if err != nil {
		t.Fatalf("exportTrace() unexpected error: %v", err)
	}
	if contentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got '%s'", contentType)
	}
}
