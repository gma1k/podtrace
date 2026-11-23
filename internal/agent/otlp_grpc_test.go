package agent

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	colmetricpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/gma1k/podtrace/pkg/exporter/bundle"
)

type grpcCollector struct {
	coltracepb.UnimplementedTraceServiceServer

	addr string

	mu       sync.Mutex
	spans    int
	metrics  int
	metadata metadata.MD
	arrived  chan struct{}
	once     sync.Once
}

func (c *grpcCollector) Export(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) (*coltracepb.ExportTraceServiceResponse, error) {
	c.mu.Lock()
	for _, rs := range req.GetResourceSpans() {
		for _, ss := range rs.GetScopeSpans() {
			c.spans += len(ss.GetSpans())
		}
	}
	c.metadata, _ = metadata.FromIncomingContext(ctx)
	c.mu.Unlock()
	c.once.Do(func() { close(c.arrived) })
	return &coltracepb.ExportTraceServiceResponse{}, nil
}

type grpcMetricsService struct {
	colmetricpb.UnimplementedMetricsServiceServer
	collector *grpcCollector
}

func (m grpcMetricsService) Export(ctx context.Context, req *colmetricpb.ExportMetricsServiceRequest) (*colmetricpb.ExportMetricsServiceResponse, error) {
	c := m.collector
	c.mu.Lock()
	c.metrics += len(req.GetResourceMetrics())
	c.metadata, _ = metadata.FromIncomingContext(ctx)
	c.mu.Unlock()
	c.once.Do(func() { close(c.arrived) })
	return &colmetricpb.ExportMetricsServiceResponse{}, nil
}

func startGRPCCollector(t *testing.T) *grpcCollector {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &grpcCollector{addr: ln.Addr().String(), arrived: make(chan struct{})}
	srv := grpc.NewServer()
	coltracepb.RegisterTraceServiceServer(srv, c)
	colmetricpb.RegisterMetricsServiceServer(srv, grpcMetricsService{collector: c})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	return c
}

func (c *grpcCollector) wait(t *testing.T) {
	t.Helper()
	select {
	case <-c.arrived:
	case <-time.After(20 * time.Second):
		t.Fatal("nothing arrived at the gRPC collector")
	}
}

func clearEgressProxy(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"PODTRACE_EGRESS_HTTP_PROXY", "PODTRACE_EGRESS_HTTPS_PROXY", "PODTRACE_EGRESS_NO_PROXY",
		"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
	} {
		t.Setenv(k, "")
	}
}

func TestGRPCProtocolSpansReachAnOTLPGRPCCollector(t *testing.T) {
	clearEgressProxy(t)
	collector := startGRPCCollector(t)

	exporter, err := newOTLPSpanExporter(&BundlePayload{
		Type:          bundle.TypeOTLP,
		Endpoint:      collector.addr,
		Protocol:      bundle.ProtocolGRPC,
		Insecure:      true,
		Headers:       map[string]string{"X-Tenant": "shop"},
		HeaderName:    "authorization",
		Credential:    []byte("Bearer secret"),
		SecretHeaders: map[string]string{"x-team": "payments"},
	})
	if err != nil {
		t.Fatalf("newOTLPSpanExporter: %v", err)
	}
	t.Cleanup(func() { _ = exporter.Shutdown(context.Background()) })

	stub := tracetest.SpanStub{Name: "probe", StartTime: time.Now(), EndTime: time.Now()}
	if err := exporter.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{stub.Snapshot()}); err != nil {
		t.Fatalf("ExportSpans over gRPC: %v; protocol: grpc must speak gRPC, not OTLP/HTTP", err)
	}
	collector.wait(t)

	collector.mu.Lock()
	defer collector.mu.Unlock()
	if collector.spans != 1 {
		t.Errorf("collector received %d spans, want 1", collector.spans)
	}
	for key, want := range map[string]string{"x-tenant": "shop", "authorization": "Bearer secret", "x-team": "payments"} {
		if got := collector.metadata.Get(key); len(got) != 1 || got[0] != want {
			t.Errorf("metadata %s = %v, want %q", key, got, want)
		}
	}
}

func TestGRPCProtocolMetricsReachAnOTLPGRPCCollector(t *testing.T) {
	clearEgressProxy(t)
	collector := startGRPCCollector(t)

	dest, wanted := destinationFromBundle(&BundlePayload{
		Type:            bundle.TypeOTLP,
		Endpoint:        "http://" + collector.addr,
		Protocol:        bundle.ProtocolGRPC,
		Metrics:         true,
		MetricsInterval: minMetricPushInterval,
		HeaderName:      "authorization",
		Credential:      []byte("Bearer secret"),
	})
	if !wanted || !dest.grpc {
		t.Fatalf("destination = %+v, want a gRPC metric destination", dest)
	}
	reader, err := newOTLPMetricReader(dest, wireProducer{})
	if err != nil {
		t.Fatalf("newOTLPMetricReader: %v", err)
	}
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	if err := provider.ForceFlush(context.Background()); err != nil {
		t.Fatalf("ForceFlush over gRPC: %v", err)
	}
	collector.wait(t)

	collector.mu.Lock()
	defer collector.mu.Unlock()
	if collector.metrics == 0 {
		t.Error("collector received no resource metrics")
	}
	if got := collector.metadata.Get("authorization"); len(got) != 1 || got[0] != "Bearer secret" {
		t.Errorf("authorization metadata = %v", got)
	}
}

func TestGRPCProtocolRefusesTheMetadataAddress(t *testing.T) {
	clearEgressProxy(t)
	exporter, err := newOTLPSpanExporter(&BundlePayload{
		Type:     bundle.TypeOTLP,
		Endpoint: "169.254.169.254:4317",
		Protocol: bundle.ProtocolGRPC,
		Insecure: true,
	})
	if err != nil {
		t.Fatalf("newOTLPSpanExporter: %v", err)
	}
	t.Cleanup(func() { _ = exporter.Shutdown(context.Background()) })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stub := tracetest.SpanStub{Name: "probe", StartTime: time.Now(), EndTime: time.Now()}
	err = exporter.ExportSpans(ctx, []sdktrace.ReadOnlySpan{stub.Snapshot()})
	if err == nil {
		t.Fatal("a gRPC export to the metadata address succeeded")
	}
	if !strings.Contains(err.Error(), "blocked by the egress guard") {
		t.Errorf("export error = %v, want the egress guard refusal", err)
	}
}

func TestGRPCMetricDestinationsDoNotShareAnHTTPPusher(t *testing.T) {
	httpDest := destination{endpoint: "collector:4317", interval: time.Minute}
	grpcDest := httpDest
	grpcDest.grpc = true
	if httpDest.key() == grpcDest.key() {
		t.Error("an HTTP and a gRPC destination share a pusher key, so one would push with the other's transport")
	}
}

func TestOnlyOTLPBundlesUseGRPC(t *testing.T) {
	for _, tc := range []struct {
		payload *BundlePayload
		want    bool
	}{
		{&BundlePayload{Type: bundle.TypeOTLP, Protocol: bundle.ProtocolGRPC}, true},
		{&BundlePayload{Type: bundle.TypeOTLP, Protocol: bundle.ProtocolHTTP}, false},
		{&BundlePayload{Type: bundle.TypeOTLP}, false},
		{&BundlePayload{Type: bundle.TypeDataDog, Protocol: bundle.ProtocolGRPC}, false},
		{nil, false},
	} {
		if got := tc.payload.UsesGRPC(); got != tc.want {
			t.Errorf("UsesGRPC(%+v) = %v, want %v", tc.payload, got, tc.want)
		}
	}
}

func TestGRPCTarget(t *testing.T) {
	yes, no := true, false
	for _, tc := range []struct {
		name         string
		endpoint     otlpEndpoint
		bundleInsec  bool
		wantHost     string
		wantInsecure bool
		wantErr      string
	}{
		{name: "host and port", endpoint: otlpEndpoint{host: "collector:4317"}, wantHost: "collector:4317"},
		{name: "default port", endpoint: otlpEndpoint{host: "collector"}, wantHost: "collector:4317"},
		{name: "bracketed ipv6 default port", endpoint: otlpEndpoint{host: "[fd00::1]"}, wantHost: "[fd00::1]:4317"},
		{name: "bundle insecure", endpoint: otlpEndpoint{host: "collector:4317"}, bundleInsec: true, wantHost: "collector:4317", wantInsecure: true},
		{name: "http scheme is cleartext", endpoint: otlpEndpoint{host: "collector:4317", insecure: &yes}, wantHost: "collector:4317", wantInsecure: true},
		{name: "https scheme wins over bundle insecure", endpoint: otlpEndpoint{host: "collector:4317", insecure: &no}, bundleInsec: true, wantHost: "collector:4317"},
		{name: "root path", endpoint: otlpEndpoint{host: "collector:4317", path: "/"}, wantHost: "collector:4317"},
		{name: "http path refused", endpoint: otlpEndpoint{host: "collector:4318", path: "/v1/traces"}, wantErr: "URL path"},
		{name: "empty host", endpoint: otlpEndpoint{}, wantErr: "no host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, insecure, err := grpcTarget(tc.endpoint, tc.bundleInsec)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if host != tc.wantHost || insecure != tc.wantInsecure {
				t.Errorf("grpcTarget = (%q, %v), want (%q, %v)", host, insecure, tc.wantHost, tc.wantInsecure)
			}
		})
	}
}

func TestGRPCBuildErrorsAreReported(t *testing.T) {
	if _, err := newOTLPSpanExporter(&BundlePayload{
		Type: bundle.TypeOTLP, Protocol: bundle.ProtocolGRPC, Endpoint: "https://collector:4318/v1/traces",
	}); err == nil || !strings.Contains(err.Error(), "URL path") {
		t.Errorf("span exporter err = %v, want the URL path refusal", err)
	}
	if _, err := newOTLPMetricReader(destination{
		endpoint: "https://collector:4318/v1/traces", grpc: true, interval: time.Minute,
	}, wireProducer{}); err == nil || !strings.Contains(err.Error(), "URL path") {
		t.Errorf("metric reader err = %v, want the URL path refusal", err)
	}

	origTrace, origMetric := newTraceExporter, newGRPCMetricExporter
	t.Cleanup(func() { newTraceExporter, newGRPCMetricExporter = origTrace, origMetric })
	newTraceExporter = func(context.Context, otlptrace.Client) (*otlptrace.Exporter, error) {
		return nil, errors.New("constructor failed")
	}
	newGRPCMetricExporter = func(context.Context, ...otlpmetricgrpc.Option) (*otlpmetricgrpc.Exporter, error) {
		return nil, errors.New("constructor failed")
	}
	if _, err := newOTLPSpanExporter(&BundlePayload{
		Type: bundle.TypeOTLP, Protocol: bundle.ProtocolGRPC, Endpoint: "collector:4317",
	}); err == nil || !strings.Contains(err.Error(), "OTLP/gRPC span exporter") {
		t.Errorf("span exporter err = %v", err)
	}
	if _, err := newOTLPMetricReader(destination{
		endpoint: "collector:4317", grpc: true, interval: time.Minute,
	}, wireProducer{}); err == nil || !strings.Contains(err.Error(), "OTLP/gRPC metric exporter") {
		t.Errorf("metric reader err = %v", err)
	}
}

func TestGRPCTransportCredentials(t *testing.T) {
	if grpcTransportCredentials(true) != nil {
		t.Error("cleartext endpoint got TLS credentials")
	}
	creds := grpcTransportCredentials(false)
	if creds == nil || creds.Info().SecurityProtocol != "tls" {
		t.Errorf("TLS endpoint credentials = %v", creds)
	}
}
