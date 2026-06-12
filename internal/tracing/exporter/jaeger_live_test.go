package exporter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/diagnose/tracker"
)

// TestJaegerLive_IngestsAndPreservesStructure runs against a REAL Jaeger
// (not an httptest stub — the old JSON exporter only ever passed against
// stubs while real Jaeger silently dropped everything). Gated behind
// PODTRACE_JAEGER_LIVE_E2E, which must point at a Jaeger OTLP endpoint
// with the query API on port 16686 of the same host.
func TestJaegerLive_IngestsAndPreservesStructure(t *testing.T) {
	endpoint := os.Getenv("PODTRACE_JAEGER_LIVE_E2E")
	if endpoint == "" {
		t.Skip("set PODTRACE_JAEGER_LIVE_E2E to a live Jaeger OTLP endpoint to run")
	}

	exporter, err := NewJaegerExporter(endpoint, 1.0)
	if err != nil {
		t.Fatalf("NewJaegerExporter: %v", err)
	}
	t.Cleanup(func() { _ = exporter.Shutdown(t.Context()) })

	traceID := fmt.Sprintf("%016x%016x", time.Now().UnixNano(), time.Now().UnixNano()>>1)
	base := time.Now().Add(-2 * time.Second)
	mkSpan := func(spanID, parentID, op string, offset time.Duration) *tracker.Span {
		return &tracker.Span{
			TraceID: traceID, SpanID: spanID, ParentSpanID: parentID,
			Operation: op, Service: "live-e2e",
			StartTime: base.Add(offset), Duration: 100 * time.Millisecond,
		}
	}
	live := &tracker.Trace{TraceID: traceID, Spans: []*tracker.Span{
		mkSpan("aaaaaaaaaaaaaaa1", "", "root", 0),
		mkSpan("aaaaaaaaaaaaaaa2", "aaaaaaaaaaaaaaa1", "child-a", 10*time.Millisecond),
		mkSpan("aaaaaaaaaaaaaaa3", "aaaaaaaaaaaaaaa1", "child-b", 20*time.Millisecond),
	}}

	if err := exporter.ExportTraces([]*tracker.Trace{live}); err != nil {
		t.Fatalf("ExportTraces: %v", err)
	}

	queryBase := "http://localhost:16686"
	var stored struct {
		Data []struct {
			Spans []struct {
				TraceID       string `json:"traceID"`
				SpanID        string `json:"spanID"`
				OperationName string `json:"operationName"`
				References    []struct {
					RefType string `json:"refType"`
					SpanID  string `json:"spanID"`
				} `json:"references"`
			} `json:"spans"`
		} `json:"data"`
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := http.Get(queryBase + "/api/traces/" + traceID)
		if err == nil {
			err = json.NewDecoder(resp.Body).Decode(&stored)
			_ = resp.Body.Close()
		}
		if err == nil && len(stored.Data) > 0 && len(stored.Data[0].Spans) == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Jaeger never stored the 3 exported spans (got %+v); the trace was not ingested", stored.Data)
		}
		time.Sleep(500 * time.Millisecond)
	}

	spans := map[string]string{}
	parents := map[string]string{}
	for _, s := range stored.Data[0].Spans {
		spans[s.SpanID] = s.OperationName
		for _, ref := range s.References {
			if ref.RefType == "CHILD_OF" {
				parents[s.SpanID] = ref.SpanID
			}
		}
	}
	for _, id := range []string{"aaaaaaaaaaaaaaa1", "aaaaaaaaaaaaaaa2", "aaaaaaaaaaaaaaa3"} {
		if _, ok := spans[id]; !ok {
			t.Errorf("span %s missing from Jaeger — original span IDs were not preserved (have %v)", id, spans)
		}
	}
	for _, child := range []string{"aaaaaaaaaaaaaaa2", "aaaaaaaaaaaaaaa3"} {
		if parents[child] != "aaaaaaaaaaaaaaa1" {
			t.Errorf("child %s parent reference = %q, want the real root aaaaaaaaaaaaaaa1", child, parents[child])
		}
	}
}
