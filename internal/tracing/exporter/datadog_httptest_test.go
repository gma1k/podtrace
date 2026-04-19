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

func newTestDataDogTrace() *tracker.Trace {
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

func TestDataDogExporter_exportTrace_HTTPSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	exporter, err := NewDataDogExporter(srv.URL, "", 1.0)
	if err != nil {
		t.Fatalf("NewDataDogExporter() error: %v", err)
	}

	err = exporter.exportTrace(newTestDataDogTrace())
	if err != nil {
		t.Errorf("exportTrace() unexpected error: %v", err)
	}
}

func TestDataDogExporter_exportTrace_HTTPAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)

	exporter, err := NewDataDogExporter(srv.URL, "", 1.0)
	if err != nil {
		t.Fatalf("NewDataDogExporter() error: %v", err)
	}

	err = exporter.exportTrace(newTestDataDogTrace())
	if err != nil {
		t.Errorf("exportTrace() unexpected error for 202: %v", err)
	}
}

func TestDataDogExporter_exportTrace_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)

	exporter, err := NewDataDogExporter(srv.URL, "", 1.0)
	if err != nil {
		t.Fatalf("NewDataDogExporter() error: %v", err)
	}

	err = exporter.exportTrace(newTestDataDogTrace())
	if err == nil {
		t.Error("expected error for 400 Bad Request, got nil")
	}
}

func TestDataDogExporter_ExportTraces_WithServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	exporter, err := NewDataDogExporter(srv.URL, "", 1.0)
	if err != nil {
		t.Fatalf("NewDataDogExporter() error: %v", err)
	}

	err = exporter.ExportTraces([]*tracker.Trace{newTestDataDogTrace()})
	if err != nil {
		t.Errorf("ExportTraces() unexpected error: %v", err)
	}
}

func TestDataDogExporter_exportTrace_SendsAPIKey(t *testing.T) {
	var receivedKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedKey = r.Header.Get("DD-API-KEY")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	exporter, err := NewDataDogExporter(srv.URL, "test-dd-key", 1.0)
	if err != nil {
		t.Fatalf("NewDataDogExporter() error: %v", err)
	}

	err = exporter.exportTrace(newTestDataDogTrace())
	if err != nil {
		t.Fatalf("exportTrace() unexpected error: %v", err)
	}
	if receivedKey != "test-dd-key" {
		t.Errorf("Expected DD-API-KEY header 'test-dd-key', got '%s'", receivedKey)
	}
}

func TestDataDogExporter_exportTrace_NoAPIKeyHeader(t *testing.T) {
	var receivedKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedKey = r.Header.Get("DD-API-KEY")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	exporter, err := NewDataDogExporter(srv.URL, "", 1.0)
	if err != nil {
		t.Fatalf("NewDataDogExporter() error: %v", err)
	}

	err = exporter.exportTrace(newTestDataDogTrace())
	if err != nil {
		t.Fatalf("exportTrace() unexpected error: %v", err)
	}
	if receivedKey != "" {
		t.Errorf("Expected no DD-API-KEY header, got '%s'", receivedKey)
	}
}

func TestDataDogExporter_exportTrace_PayloadFormat(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	exporter, err := NewDataDogExporter(srv.URL, "", 1.0)
	if err != nil {
		t.Fatalf("NewDataDogExporter() error: %v", err)
	}

	err = exporter.exportTrace(newTestDataDogTrace())
	if err != nil {
		t.Fatalf("exportTrace() unexpected error: %v", err)
	}

	// Payload must be a 2D array (array of trace arrays).
	var payload [][]datadogSpan
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}
	if len(payload) != 1 {
		t.Errorf("expected 1 trace in payload, got %d", len(payload))
	}
	if len(payload[0]) != 1 {
		t.Errorf("expected 1 span in trace, got %d", len(payload[0]))
	}
	span := payload[0][0]
	if span.Service != "test-service" {
		t.Errorf("expected service 'test-service', got '%s'", span.Service)
	}
	if span.Name != "test-op" {
		t.Errorf("expected name 'test-op', got '%s'", span.Name)
	}
}

func TestDataDogExporter_exportTrace_ErrorFlagInPayload(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	exporter, err := NewDataDogExporter(srv.URL, "", 1.0)
	if err != nil {
		t.Fatalf("NewDataDogExporter() error: %v", err)
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

	var payload [][]datadogSpan
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}
	if payload[0][0].Error != 1 {
		t.Errorf("expected error=1 for error span, got %d", payload[0][0].Error)
	}
}
