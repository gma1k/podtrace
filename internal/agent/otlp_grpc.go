package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/netguard"
)

var newGRPCMetricExporter = otlpmetricgrpc.New

// otlpGRPCDefaultPort is the OTLP/gRPC receiver port every collector
// listens on by default.
const otlpGRPCDefaultPort = "4317"

// grpcTarget resolves an OTLP endpoint into the host:port gRPC dials and
// whether the connection is cleartext. A gRPC endpoint has no URL path, so
// one is refused rather than silently dropped: it usually means an
// OTLP/HTTP URL was paired with protocol: grpc.
func grpcTarget(endpoint otlpEndpoint, bundleInsecure bool) (string, bool, error) {
	if endpoint.path != "" && endpoint.path != "/" {
		return "", false, fmt.Errorf("OTLP/gRPC endpoint %q has a URL path %q; gRPC takes host:port only (use protocol: http for an OTLP/HTTP URL)", endpoint.host, endpoint.path)
	}
	host := endpoint.host
	if host == "" {
		return "", false, fmt.Errorf("OTLP/gRPC endpoint has no host")
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(trimBrackets(host), otlpGRPCDefaultPort)
	}
	insecure := bundleInsecure
	if endpoint.insecure != nil {
		insecure = *endpoint.insecure
	}
	return host, insecure, nil
}

func trimBrackets(host string) string {
	if len(host) > 1 && host[0] == '[' && host[len(host)-1] == ']' {
		return host[1 : len(host)-1]
	}
	return host
}

// grpcTransportCredentials is TLS with the system roots unless the
// endpoint is cleartext.
func grpcTransportCredentials(insecure bool) credentials.TransportCredentials {
	if insecure {
		return nil
	}
	return credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
}

// grpcDialOptions routes every gRPC exporter connection through the egress
// guard, which also carries the egress proxy.
func grpcDialOptions() []grpc.DialOption {
	return []grpc.DialOption{grpc.WithContextDialer(netguard.DialGRPC)}
}

func newOTLPGRPCSpanExporter(b *BundlePayload, endpoint otlpEndpoint) (*otlptrace.Exporter, error) {
	host, insecure, err := grpcTarget(endpoint, b.Insecure)
	if err != nil {
		return nil, fmt.Errorf("bundle endpoint: %w", err)
	}
	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(netguard.GRPCTarget(host)),
		otlptracegrpc.WithTimeout(config.TracingExporterTimeout),
		otlptracegrpc.WithDialOption(grpcDialOptions()...),
	}
	if creds := grpcTransportCredentials(insecure); creds != nil {
		opts = append(opts, otlptracegrpc.WithTLSCredentials(creds))
	} else {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	if headers := bundleHeaders(b); len(headers) > 0 {
		opts = append(opts, otlptracegrpc.WithHeaders(headers))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	spanExporter, err := newTraceExporter(ctx, otlptracegrpc.NewClient(opts...))
	if err != nil {
		return nil, fmt.Errorf("create OTLP/gRPC span exporter: %w", err)
	}
	return spanExporter, nil
}

func newOTLPGRPCMetricReader(dest destination, endpoint otlpEndpoint, producer sdkmetric.Producer) (sdkmetric.Reader, error) {
	host, insecure, err := grpcTarget(endpoint, dest.insecure)
	if err != nil {
		return nil, fmt.Errorf("bundle endpoint: %w", err)
	}
	opts := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithEndpoint(netguard.GRPCTarget(host)),
		otlpmetricgrpc.WithTimeout(config.TracingExporterTimeout),
		otlpmetricgrpc.WithDialOption(grpcDialOptions()...),
	}
	if creds := grpcTransportCredentials(insecure); creds != nil {
		opts = append(opts, otlpmetricgrpc.WithTLSCredentials(creds))
	} else {
		opts = append(opts, otlpmetricgrpc.WithInsecure())
	}
	if len(dest.headers) > 0 {
		opts = append(opts, otlpmetricgrpc.WithHeaders(dest.headers))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	exporter, err := newGRPCMetricExporter(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create OTLP/gRPC metric exporter: %w", err)
	}
	return newPeriodicMetricReader(exporter, dest, producer), nil
}
