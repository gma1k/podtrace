package exporter

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/diagnose/tracker"
	"github.com/podtrace/podtrace/internal/events"
)

// ─── normalizeOTLPHTTPEndpoint ────────────────────────────────────────────────

func TestNormalizeOTLPHTTPEndpoint_EmptyUsesDefault(t *testing.T) {
	urlStr, _, err := normalizeOTLPHTTPEndpoint("")
	if err != nil {
		t.Fatalf("unexpected error for empty endpoint: %v", err)
	}
	if urlStr == "" {
		t.Error("expected a non-empty default endpoint URL")
	}
}

func TestNormalizeOTLPHTTPEndpoint_SchemelessHostPort(t *testing.T) {
	urlStr, insecure, err := normalizeOTLPHTTPEndpoint("localhost:4318")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !insecure {
		t.Error("expected insecure=true for loopback http endpoint")
	}
	if !strings.HasPrefix(urlStr, "http://") {
		t.Errorf("expected http:// prefix, got %q", urlStr)
	}
}

func TestNormalizeOTLPHTTPEndpoint_HTTPSReturnsSecure(t *testing.T) {
	urlStr, insecure, err := normalizeOTLPHTTPEndpoint("https://collector.example:4318")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if insecure {
		t.Error("expected insecure=false for https endpoint")
	}
	if !strings.HasPrefix(urlStr, "https://") {
		t.Errorf("expected https:// prefix, got %q", urlStr)
	}
}

func TestNormalizeOTLPHTTPEndpoint_MalformedURL(t *testing.T) {
	_, _, err := normalizeOTLPHTTPEndpoint("http://\x7f/bad")
	if err == nil {
		t.Fatal("expected parse error for malformed URL")
	}
	if !strings.Contains(err.Error(), "parse OTLP endpoint") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNormalizeOTLPHTTPEndpoint_BadScheme(t *testing.T) {
	_, _, err := normalizeOTLPHTTPEndpoint("ftp://collector.example:4318")
	if err == nil {
		t.Fatal("expected error for non-http(s) scheme")
	}
	if !strings.Contains(err.Error(), "scheme") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNormalizeOTLPHTTPEndpoint_RemoteCleartextRejected(t *testing.T) {
	_, _, err := normalizeOTLPHTTPEndpoint("http://collector.example:4318")
	if err == nil {
		t.Fatal("expected error refusing cleartext http to non-loopback host")
	}
	if !strings.Contains(err.Error(), "cleartext") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ─── exportSpan DNS event branch ──────────────────────────────────────────────

func TestOTLPExporter_exportSpan_DNSEvent(t *testing.T) {
	exporter, err := NewOTLPExporter("http://localhost:4318", 1.0)
	if err != nil {
		t.Skipf("failed to create exporter: %v", err)
	}
	defer func() { _ = exporter.Shutdown(context.Background()) }()

	span := &tracker.Span{
		TraceID:   "12345678901234567890123456789012",
		SpanID:    "1234567890123456",
		Operation: "dns-lookup",
		StartTime: time.Now(),
		Duration:  5 * time.Millisecond,
		Events: []*events.Event{
			{
				Type:         events.EventDNS,
				Target:       "example.com",
				Timestamp:    uint64(time.Now().UnixNano()),
				LatencyNS:    2_000_000,
				TCPState:     1,               // dns.question.type
				Error:        0,               // dns.response.code
				Details:      "93.184.216.34", // dns.resolved
				DNSServerIP:  0x08080808,      // dns.server (non-zero → emitted)
				DNSTransport: 1,               // dns.transport=tcp
			},
		},
	}

	if err := exporter.exportSpan(context.Background(), span, &tracker.Trace{TraceID: "t"}); err != nil {
		t.Errorf("exportSpan() unexpected error: %v", err)
	}
}

func TestOTLPExporter_exportSpan_DNSEvent_MinimalFields(t *testing.T) {
	exporter, err := NewOTLPExporter("http://localhost:4318", 1.0)
	if err != nil {
		t.Skipf("failed to create exporter: %v", err)
	}
	defer func() { _ = exporter.Shutdown(context.Background()) }()

	span := &tracker.Span{
		TraceID:   "12345678901234567890123456789012",
		SpanID:    "1234567890123456",
		Operation: "dns-lookup",
		StartTime: time.Now(),
		Duration:  5 * time.Millisecond,
		Events: []*events.Event{
			{
				Type:         events.EventDNS,
				Target:       "example.com",
				Timestamp:    uint64(time.Now().UnixNano()),
				LatencyNS:    1_000_000,
				Details:      "",
				DNSServerIP:  0,
				DNSTransport: 0,
			},
		},
	}

	if err := exporter.exportSpan(context.Background(), span, &tracker.Trace{TraceID: "t"}); err != nil {
		t.Errorf("exportSpan() unexpected error: %v", err)
	}
}
