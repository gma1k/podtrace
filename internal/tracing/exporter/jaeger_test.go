package exporter

import (
	"context"
	"testing"

	"github.com/podtrace/podtrace/internal/diagnose/tracker"
)

func TestNewJaegerExporter_DefaultEndpointTranslatesToOTLP(t *testing.T) {
	exporter, err := NewJaegerExporter("", 1.0)
	if err != nil {
		t.Fatalf("NewJaegerExporter() error = %v", err)
	}
	defer func() { _ = exporter.Shutdown(context.Background()) }()
	// The legacy default (localhost:14268/api/traces) speaks Thrift; the
	// exporter must target the collector's OTLP listener instead.
	if exporter.endpoint != "http://localhost:4318" {
		t.Errorf("endpoint = %q, want the translated OTLP endpoint", exporter.endpoint)
	}
}

func TestJaegerToOTLPEndpoint(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "http://localhost:4318"},
		{"http://localhost:14268/api/traces", "http://localhost:4318"},
		{"http://jaeger-collector:14268/api/traces", "http://jaeger-collector:4318"},
		{"https://jaeger.example.com/api/traces", "https://jaeger.example.com"},
		{"http://localhost:4318", "http://localhost:4318"},
		{"https://jaeger.example.com:4318", "https://jaeger.example.com:4318"},
	}
	for _, c := range cases {
		if got := jaegerToOTLPEndpoint(c.in); got != c.want {
			t.Errorf("jaegerToOTLPEndpoint(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestJaegerExporter_ExportTraces_Empty(t *testing.T) {
	exporter, err := NewJaegerExporter("", 1.0)
	if err != nil {
		t.Fatalf("NewJaegerExporter() error = %v", err)
	}
	defer func() { _ = exporter.Shutdown(context.Background()) }()
	if err := exporter.ExportTraces([]*tracker.Trace{}); err != nil {
		t.Errorf("ExportTraces() error = %v", err)
	}
}

func TestJaegerExporter_ExportTraces_NotSampled(t *testing.T) {
	exporter, err := NewJaegerExporter("", 0.0)
	if err != nil {
		t.Fatalf("NewJaegerExporter() error = %v", err)
	}
	defer func() { _ = exporter.Shutdown(context.Background()) }()
	traces := errorSurfaceTrace()
	if err := exporter.ExportTraces(traces); err != nil {
		t.Errorf("ExportTraces() with rate 0 must be a no-op, got %v", err)
	}
}

func TestJaegerExporter_Shutdown(t *testing.T) {
	exporter, err := NewJaegerExporter("", 1.0)
	if err != nil {
		t.Fatalf("NewJaegerExporter() error = %v", err)
	}
	if err := exporter.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}
}
