package agent

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/otel/attribute"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"

	"github.com/gma1k/podtrace/internal/events"
)

func TestSDKEventExporter_InvalidUTF8DoesNotDropTheBatch(t *testing.T) {
	cs := newCaptureServer()
	defer cs.close()

	exp, err := newOTLPEventExporter(CRKey{"ns", "cr"}, &BundlePayload{Type: "otlp", Endpoint: cs.endpointHostPort(), Insecure: true})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	now := uint64(time.Now().UnixNano())
	batch := make([]*events.Event, 0, 52)
	for i := 0; i < 50; i++ {
		batch = append(batch, &events.Event{Type: events.EventOpen, Timestamp: now, Target: "/etc/ok"})
	}
	batch = append(batch,
		&events.Event{Type: events.EventOpen, Timestamp: now, Target: "/data/caf\xc3"},
		&events.Event{Type: events.EventDNS, Timestamp: now, Target: "example.test", Details: "10.0.0.1\xff"},
	)
	if err := exp.Export(context.Background(), batch); err != nil {
		t.Fatalf("Export: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := exp.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if cs.hitCount() == 0 {
		t.Fatal("no OTLP request reached the collector: one invalid string dropped the whole batch")
	}
	cs.mu.Lock()
	body := cs.lastReq.body
	cs.mu.Unlock()
	var req coltracepb.ExportTraceServiceRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	spans := 0
	sawReplacement := false
	for _, rs := range req.ResourceSpans {
		for _, ss := range rs.ScopeSpans {
			for _, sp := range ss.Spans {
				spans++
				if strings.Contains(sp.Name, "caf�") {
					sawReplacement = true
				}
			}
		}
	}
	if spans != len(batch) {
		t.Errorf("spans delivered = %d, want %d", spans, len(batch))
	}
	if !sawReplacement {
		t.Error("span name with a cut rune should carry U+FFFD in its place")
	}
}

func TestValidUTF8Attributes_ReplacesOnlyInvalidStrings(t *testing.T) {
	attrs := validUTF8Attributes([]attribute.KeyValue{
		attribute.String("ok", "plain"),
		attribute.String("bad", "x\xffy"),
		attribute.Int("n", 7),
	})
	if got := attrs[0].Value.AsString(); got != "plain" {
		t.Errorf("valid string changed: %q", got)
	}
	if got := attrs[1].Value.AsString(); !utf8.ValidString(got) || got != "x�y" {
		t.Errorf("invalid string = %q, want x\\uFFFDy", got)
	}
	if got := attrs[2].Value.AsInt64(); got != 7 {
		t.Errorf("int attribute changed: %d", got)
	}
}
