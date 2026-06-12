package exporter

import (
	"context"
	"net/url"
	"strings"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/diagnose/tracker"
)

// JaegerExporter ships traces to Jaeger over OTLP/HTTP.
//
// The previous implementation POSTed a homegrown JSON shape (modeled on the
// Jaeger UI's read API) to the collector endpoint. No Jaeger collector
// release ingests that: the legacy /api/traces endpoint speaks Thrift, and
// modern Jaeger (1.35+, and all of v2) ingests OTLP natively on :4318.
// Only the httptest stubs in our own tests ever accepted those payloads.
// Delegating to the OTLP exporter makes the spans actually land in Jaeger,
// with their original span IDs and parent/child structure.
type JaegerExporter struct {
	inner    *OTLPExporter
	endpoint string
}

func NewJaegerExporter(endpoint string, sampleRate float64) (*JaegerExporter, error) {
	otlpEndpoint := jaegerToOTLPEndpoint(endpoint)
	inner, err := NewOTLPExporter(otlpEndpoint, sampleRate)
	if err != nil {
		return nil, err
	}
	return &JaegerExporter{inner: inner, endpoint: otlpEndpoint}, nil
}

// jaegerToOTLPEndpoint translates a legacy Jaeger collector URL into the
// collector's OTLP/HTTP endpoint: the "/api/traces" suffix is dropped and
// the classic Thrift port 14268 becomes the OTLP port 4318. Endpoints that
// already point at an OTLP listener pass through unchanged.
func jaegerToOTLPEndpoint(endpoint string) string {
	raw := strings.TrimSpace(endpoint)
	if raw == "" {
		raw = config.DefaultJaegerEndpoint
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		u, err = url.Parse("http://" + raw)
		if err != nil || u.Host == "" {
			return raw
		}
	}
	u.Path = strings.TrimSuffix(u.Path, "/api/traces")
	if u.Port() == "14268" {
		u.Host = u.Hostname() + ":4318"
	}
	return u.String()
}

func (e *JaegerExporter) ExportTraces(traces []*tracker.Trace) error {
	return e.inner.ExportTraces(traces)
}

func (e *JaegerExporter) Shutdown(ctx context.Context) error {
	return e.inner.Shutdown(ctx)
}
