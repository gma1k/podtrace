package exporter

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/diagnose/tracker"
)

func TestValidateExporterEndpoint_ParseErrors(t *testing.T) {
	const def = "http://localhost:8126/v0.4/traces"

	if _, err := validateExporterEndpoint("http://\x7f/bad", def); err == nil {
		t.Error("expected a parse error for an endpoint with a control character")
	}
	if _, err := validateExporterEndpoint("a b", def); err == nil {
		t.Error("expected a parse error when the scheme-prefixed retry fails")
	}
}

func TestNormalizeOTLPHTTPEndpoint_SecondParseError(t *testing.T) {
	if _, _, err := normalizeOTLPHTTPEndpoint("a b"); err == nil {
		t.Error("expected a parse error when the scheme-prefixed retry fails")
	}
}

func TestNewJaegerExporter_BadTranslatedEndpoint(t *testing.T) {
	if _, err := NewJaegerExporter("ftp://collector:14268/api/traces", 1.0); err == nil {
		t.Error("expected an error when the translated OTLP endpoint has an unsupported scheme")
	}
}

func TestJaegerToOTLPEndpoint_UnparseableReturnsRaw(t *testing.T) {
	if got := jaegerToOTLPEndpoint("a b"); got != "a b" {
		t.Errorf("jaegerToOTLPEndpoint(%q) = %q, want the raw input echoed back", "a b", got)
	}
}

func TestExporters_RequestConstructionErrorSurfaced(t *testing.T) {
	const badEndpoint = "http://\x7f/collect"
	traces := errorSurfaceTrace()

	datadog := &DataDogExporter{enabled: true, endpoint: badEndpoint, client: &http.Client{}, sampleRate: 1.0}
	if err := datadog.ExportTraces(traces); err == nil {
		t.Error("datadog: expected an error when the request cannot be constructed")
	}

	splunk := &SplunkExporter{enabled: true, endpoint: badEndpoint, client: &http.Client{}, sampleRate: 1.0}
	if err := splunk.ExportTraces(traces); err == nil {
		t.Error("splunk: expected an error when the request cannot be constructed")
	}

	zipkin := &ZipkinExporter{enabled: true, endpoint: badEndpoint, client: &http.Client{}, sampleRate: 1.0}
	if err := zipkin.ExportTraces(traces); err == nil {
		t.Error("zipkin: expected an error when the request cannot be constructed")
	}
}

func TestOTLPExporter_spanSnapshot_InvalidParentSpanID(t *testing.T) {
	exp, err := NewOTLPExporter("http://localhost:4318", 1.0)
	if err != nil {
		t.Skipf("cannot create OTLP exporter: %v", err)
	}
	defer func() { _ = exp.Shutdown(context.Background()) }()

	span := &tracker.Span{
		TraceID:      "12345678901234567890123456789012",
		SpanID:       "1234567890123456",
		ParentSpanID: "not-hex",
		Operation:    "op",
		StartTime:    time.Now(),
		Duration:     time.Millisecond,
	}
	if _, err := exp.spanSnapshot(span); err == nil {
		t.Error("expected an error for an invalid parent span ID")
	} else if !strings.Contains(err.Error(), "parent span ID") {
		t.Errorf("error %q does not mention the parent span ID", err.Error())
	}
}
