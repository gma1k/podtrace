package exporter

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/gma1k/podtrace/internal/diagnose/tracker"
	"github.com/gma1k/podtrace/internal/events"
)

func TestOTLPExporter_InvalidUTF8DoesNotDropTheBatch(t *testing.T) {
	var mu sync.Mutex
	var bodies [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, body)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exporter, err := NewOTLPExporter(srv.URL, 1.0)
	if err != nil {
		t.Fatalf("NewOTLPExporter: %v", err)
	}
	t.Cleanup(func() { _ = exporter.Shutdown(t.Context()) })

	good := newTestTrace()
	bad := &tracker.Trace{
		TraceID: "fedcba9876543210fedcba9876543210",
		Spans: []*tracker.Span{{
			TraceID:    "fedcba9876543210fedcba9876543210",
			SpanID:     "fedcba9876543210",
			Operation:  "GET /caf\xc3",
			StartTime:  time.Now(),
			Duration:   time.Millisecond,
			Attributes: map[string]string{"http.target": "/caf\xc3", "process\xff": "ok"},
			Events: []*events.Event{
				{Type: events.EventDNS, Target: "bad\xff.example", Details: "10.0.0.1\xfe"},
			},
		}},
	}
	if err := exporter.ExportTraces([]*tracker.Trace{good, bad}); err != nil {
		t.Fatalf("ExportTraces: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) == 0 {
		t.Fatal("no request reached the collector: one invalid string dropped the whole batch")
	}
	spans := 0
	for _, body := range bodies {
		var req coltracepb.ExportTraceServiceRequest
		if err := proto.Unmarshal(body, &req); err != nil {
			t.Fatalf("decode: %v", err)
		}
		for _, rs := range req.ResourceSpans {
			for _, ss := range rs.ScopeSpans {
				for _, sp := range ss.Spans {
					spans++
					if !utf8.ValidString(sp.Name) {
						t.Errorf("span name %q is not valid UTF-8", sp.Name)
					}
					if strings.HasPrefix(sp.Name, "GET ") && sp.Name != "GET /caf�" {
						t.Errorf("span name = %q, want the cut rune replaced", sp.Name)
					}
				}
			}
		}
	}
	if spans != 2 {
		t.Errorf("spans delivered = %d, want both traces' spans", spans)
	}
}
