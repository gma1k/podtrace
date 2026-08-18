package exporter

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/diagnose/tracker"
)

func TestSplunkExporter_BatchesSpansIntoOneRequest(t *testing.T) {
	var requests int32
	var events int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		body, _ := io.ReadAll(r.Body)
		atomic.AddInt32(&events, int32(bytes.Count(bytes.TrimSpace(body), []byte("\n"))+1))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exporter, err := NewSplunkExporter(srv.URL, "tok", 1.0)
	if err != nil {
		t.Fatalf("NewSplunkExporter() error = %v", err)
	}
	exporter.client = srv.Client()

	spans := make([]*tracker.Span, 10)
	for i := range spans {
		spans[i] = &tracker.Span{TraceID: "t1", SpanID: string(rune('a' + i)), StartTime: time.Now()}
	}
	if err := exporter.ExportTraces([]*tracker.Trace{{TraceID: "t1", Spans: spans}}); err != nil {
		t.Fatalf("ExportTraces() error = %v", err)
	}

	if n := atomic.LoadInt32(&requests); n != 1 {
		t.Errorf("10 spans produced %d HTTP requests, want 1 batched request", n)
	}
	if n := atomic.LoadInt32(&events); n != 10 {
		t.Errorf("batch carried %d HEC events, want 10", n)
	}
}

func TestSplunkExporter_SplitsOversizeBatch(t *testing.T) {
	var requests int32
	var events int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		body, _ := io.ReadAll(r.Body)
		if len(body) > splunkMaxBatchBytes*2 {
			t.Errorf("batch body %d bytes exceeds the flush threshold by too much", len(body))
		}
		atomic.AddInt32(&events, int32(bytes.Count(bytes.TrimSpace(body), []byte("\n"))+1))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exporter, err := NewSplunkExporter(srv.URL, "tok", 1.0)
	if err != nil {
		t.Fatalf("NewSplunkExporter() error = %v", err)
	}
	exporter.client = srv.Client()

	const spanCount = 150
	blob := strings.Repeat("x", 8192)
	spans := make([]*tracker.Span, spanCount)
	for i := range spans {
		spans[i] = &tracker.Span{
			TraceID:    "t1",
			SpanID:     "s",
			StartTime:  time.Now(),
			Attributes: map[string]string{"blob": blob},
		}
	}
	if err := exporter.ExportTraces([]*tracker.Trace{{TraceID: "t1", Spans: spans}}); err != nil {
		t.Fatalf("ExportTraces() error = %v", err)
	}

	if n := atomic.LoadInt32(&requests); n < 2 {
		t.Errorf("an oversize export produced %d requests, want it split into >= 2 batches", n)
	}
	if n := atomic.LoadInt32(&events); n != spanCount {
		t.Errorf("batches carried %d events total, want %d", n, spanCount)
	}
}
