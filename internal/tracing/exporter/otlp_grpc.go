package exporter

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/netguard"
)

// otlpGRPCDefaultPort is the OTLP/gRPC receiver port every collector
// listens on by default.
const otlpGRPCDefaultPort = "4317"

// normalizeOTLPGRPCEndpoint returns the host:port gRPC dials and whether
// the connection is cleartext, with the same cleartext rule as OTLP/HTTP:
// http:// (or no scheme) is allowed to loopback, or anywhere once
// PODTRACE_OTLP_INSECURE is set. A URL path is refused: gRPC has none, and
// one usually means an OTLP/HTTP URL was paired with protocol: grpc.
func normalizeOTLPGRPCEndpoint(endpoint string) (string, bool, error) {
	raw := strings.TrimSpace(endpoint)
	if raw == "" {
		return "", false, fmt.Errorf("otlp: empty gRPC endpoint")
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false, fmt.Errorf("parse OTLP endpoint: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false, fmt.Errorf("otlp endpoint scheme must be http or https")
	}
	if u.Hostname() == "" {
		return "", false, fmt.Errorf("otlp: gRPC endpoint %q has no host", endpoint)
	}
	if u.Path != "" && u.Path != "/" {
		return "", false, fmt.Errorf("otlp: gRPC endpoint %q has a URL path %q; gRPC takes host:port only (use protocol: http for an OTLP/HTTP URL)", endpoint, u.Path)
	}
	port := u.Port()
	if port == "" {
		port = otlpGRPCDefaultPort
	}
	target := net.JoinHostPort(u.Hostname(), port)
	if u.Scheme == "https" {
		return target, false, nil
	}
	if isLoopbackHost(u.Hostname()) || config.OTLPAllowInsecureNonLoopback() {
		return target, true, nil
	}
	return "", false, fmt.Errorf("otlp: refusing cleartext gRPC to %q; use https:// or set PODTRACE_OTLP_INSECURE=1", u.Hostname())
}

// newOTLPGRPCSpanExporter builds the OTLP/gRPC trace client. It dials
// through the egress guard (which also carries the egress proxy) and uses
// the OTEL_EXPORTER_OTLP_* certificate variables the HTTP client honours.
func newOTLPGRPCSpanExporter(ctx context.Context, endpoint string) (sdktrace.SpanExporter, string, error) {
	target, useInsecure, err := normalizeOTLPGRPCEndpoint(endpoint)
	if err != nil {
		return nil, "", err
	}
	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(netguard.GRPCTarget(target)),
		otlptracegrpc.WithTimeout(config.TracingExporterTimeout),
		otlptracegrpc.WithRetry(otlptracegrpc.RetryConfig{Enabled: false}),
		otlptracegrpc.WithDialOption(grpc.WithContextDialer(netguard.DialGRPC)),
	}
	if useInsecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	} else {
		tlsConfig, err := otlpTLSConfigFromEnv()
		if err != nil {
			return nil, "", err
		}
		if tlsConfig == nil {
			tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		opts = append(opts, otlptracegrpc.WithTLSCredentials(credentials.NewTLS(tlsConfig)))
	}
	if len(config.OTLPHeaders) > 0 {
		headers := make(map[string]string, len(config.OTLPHeaders))
		for k, v := range config.OTLPHeaders {
			headers[k] = v
		}
		opts = append(opts, otlptracegrpc.WithHeaders(headers))
	}
	exporter, err := newOTLPGRPCClient(ctx, opts...)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create OTLP/gRPC exporter: %w", err)
	}
	scheme := "https"
	if useInsecure {
		scheme = "http"
	}
	return guardedGRPCSpanExporter{exporter}, scheme + "://" + target, nil
}

// guardedGRPCSpanExporter keeps an egress-guard refusal recognisable as
// one after gRPC has flattened it into a status, so the trace is dropped
// as permanent instead of being offered again on every flush.
type guardedGRPCSpanExporter struct {
	sdktrace.SpanExporter
}

func (e guardedGRPCSpanExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	return netguard.RecoverBlocked(e.SpanExporter.ExportSpans(ctx, spans))
}
