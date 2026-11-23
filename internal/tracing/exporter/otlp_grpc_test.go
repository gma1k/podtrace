package exporter

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/diagnose/tracker"
	"github.com/gma1k/podtrace/internal/netguard"
)

type sessionGRPCCollector struct {
	coltracepb.UnimplementedTraceServiceServer

	mu       sync.Mutex
	spans    int
	metadata metadata.MD
}

func (c *sessionGRPCCollector) Export(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) (*coltracepb.ExportTraceServiceResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, rs := range req.GetResourceSpans() {
		for _, ss := range rs.GetScopeSpans() {
			c.spans += len(ss.GetSpans())
		}
	}
	c.metadata, _ = metadata.FromIncomingContext(ctx)
	return &coltracepb.ExportTraceServiceResponse{}, nil
}

func startSessionGRPCCollector(t *testing.T, opts ...grpc.ServerOption) (*sessionGRPCCollector, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &sessionGRPCCollector{}
	srv := grpc.NewServer(opts...)
	coltracepb.RegisterTraceServiceServer(srv, c)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	return c, ln.Addr().String()
}

func useGRPCProtocol(t *testing.T) {
	t.Helper()
	config.OTLPProtocol = config.OTLPProtocolGRPC
	t.Cleanup(func() { config.OTLPProtocol = "" })
}

func TestSessionGRPCSpansReachAnOTLPGRPCCollector(t *testing.T) {
	useGRPCProtocol(t)
	config.OTLPHeaders = map[string]string{"X-Tenant": "shop"}
	t.Cleanup(func() { config.OTLPHeaders = nil })
	collector, addr := startSessionGRPCCollector(t)

	exp, err := NewOTLPExporter("http://"+addr, 1.0)
	if err != nil {
		t.Fatalf("NewOTLPExporter: %v", err)
	}
	t.Cleanup(func() { _ = exp.Shutdown(context.Background()) })
	if exp.endpoint != "http://"+addr {
		t.Errorf("endpoint = %q", exp.endpoint)
	}
	if err := exp.ExportTraces([]*tracker.Trace{traceWithIDs(goodTraceID, "1122334455667788")}); err != nil {
		t.Fatalf("export over gRPC: %v", err)
	}

	collector.mu.Lock()
	defer collector.mu.Unlock()
	if collector.spans == 0 {
		t.Fatal("the collector received no spans")
	}
	if got := collector.metadata.Get("x-tenant"); len(got) != 1 || got[0] != "shop" {
		t.Errorf("x-tenant metadata = %v", got)
	}
}

func TestSessionGRPCTrustsTheCAFromTheStandardEnvironment(t *testing.T) {
	useGRPCProtocol(t)
	issuer := httptest.NewUnstartedServer(http.NotFoundHandler())
	issuer.StartTLS()
	t.Cleanup(issuer.Close)
	serverCreds := credentials.NewTLS(&tls.Config{Certificates: issuer.TLS.Certificates, MinVersion: tls.VersionTLS12})
	collector, addr := startSessionGRPCCollector(t, grpc.Creds(serverCreds))
	t.Setenv("OTEL_EXPORTER_OTLP_CERTIFICATE", writeCollectorCA(t, issuer))

	exp, err := NewOTLPExporter("https://"+addr, 1.0)
	if err != nil {
		t.Fatalf("NewOTLPExporter: %v", err)
	}
	t.Cleanup(func() { _ = exp.Shutdown(context.Background()) })
	if err := exp.ExportTraces([]*tracker.Trace{traceWithIDs(goodTraceID, "1122334455667788")}); err != nil {
		t.Fatalf("export over gRPC with TLS: %v", err)
	}
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if collector.spans == 0 {
		t.Fatal("the collector received no spans over TLS")
	}
}

func TestSessionGRPCMetadataRefusalIsNotRetried(t *testing.T) {
	useGRPCProtocol(t)
	t.Setenv("PODTRACE_OTLP_INSECURE", "1")
	exp, err := NewOTLPExporter("http://169.254.169.254:4317", 1.0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exp.Shutdown(context.Background()) })

	err = exp.ExportTraces([]*tracker.Trace{traceWithIDs(goodTraceID, "1122334455667788")})
	if !errors.Is(err, netguard.ErrBlocked) {
		t.Fatalf("error does not wrap netguard.ErrBlocked: %v", err)
	}
	var partial *PartialExportError
	if !errors.As(err, &partial) || partial.Retry(goodTraceID) {
		t.Fatalf("a trace refused by the egress guard must be dropped as permanent, got %v", err)
	}
}

func TestSessionGRPCReportsATLSConfigurationError(t *testing.T) {
	useGRPCProtocol(t)
	certPath, _ := writeClientKeyPair(t, "first")
	_, otherKeyPath := writeClientKeyPair(t, "second")
	t.Setenv("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE", certPath)
	t.Setenv("OTEL_EXPORTER_OTLP_CLIENT_KEY", otherKeyPath)

	if _, err := NewOTLPExporter("https://collector.example:4317", 1.0); err == nil || !strings.Contains(err.Error(), "client certificate") {
		t.Fatalf("err = %v, want the client certificate error", err)
	}
}

func TestSessionGRPCReportsAConstructorError(t *testing.T) {
	useGRPCProtocol(t)
	orig := newOTLPGRPCClient
	t.Cleanup(func() { newOTLPGRPCClient = orig })
	newOTLPGRPCClient = func(context.Context, ...otlptracegrpc.Option) (*otlptrace.Exporter, error) {
		return nil, errors.New("boom client")
	}
	if _, err := NewOTLPExporter("https://collector.example:4317", 1.0); err == nil || !strings.Contains(err.Error(), "OTLP/gRPC exporter") {
		t.Fatalf("err = %v, want the gRPC constructor error", err)
	}
}

func TestSessionGRPCRefusesAnInvalidEndpoint(t *testing.T) {
	useGRPCProtocol(t)
	if _, err := NewOTLPExporter("https://collector.example:4318/v1/traces", 1.0); err == nil || !strings.Contains(err.Error(), "URL path") {
		t.Fatalf("err = %v, want the URL path refusal", err)
	}
}

func TestNormalizeOTLPGRPCEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name         string
		endpoint     string
		allowInsec   bool
		wantTarget   string
		wantInsecure bool
		wantErr      string
	}{
		{name: "https", endpoint: "https://collector.example:4317", wantTarget: "collector.example:4317"},
		{name: "https default port", endpoint: "https://collector.example", wantTarget: "collector.example:4317"},
		{name: "ipv6 default port", endpoint: "https://[fd00::1]", wantTarget: "[fd00::1]:4317"},
		{name: "root path", endpoint: "https://collector.example:4317/", wantTarget: "collector.example:4317"},
		{name: "loopback cleartext", endpoint: "http://127.0.0.1:4317", wantTarget: "127.0.0.1:4317", wantInsecure: true},
		{name: "schemeless loopback", endpoint: "localhost:4317", wantTarget: "localhost:4317", wantInsecure: true},
		{name: "cleartext allowed by opt-in", endpoint: "http://otel.observability:4317", allowInsec: true, wantTarget: "otel.observability:4317", wantInsecure: true},
		{name: "cleartext refused", endpoint: "http://otel.observability:4317", wantErr: "refusing cleartext gRPC"},
		{name: "path refused", endpoint: "https://collector.example:4318/v1/traces", wantErr: "URL path"},
		{name: "empty", endpoint: "  ", wantErr: "empty gRPC endpoint"},
		{name: "bad scheme", endpoint: "ftp://collector.example", wantErr: "scheme must be http or https"},
		{name: "no host", endpoint: "https://:4317", wantErr: "has no host"},
		{name: "unparseable", endpoint: "https://collector.example:bad port", wantErr: "parse OTLP endpoint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.allowInsec {
				t.Setenv("PODTRACE_OTLP_INSECURE", "1")
			} else {
				t.Setenv("PODTRACE_OTLP_INSECURE", "")
			}
			target, insecure, err := normalizeOTLPGRPCEndpoint(tc.endpoint)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if target != tc.wantTarget || insecure != tc.wantInsecure {
				t.Errorf("got (%q, %v), want (%q, %v)", target, insecure, tc.wantTarget, tc.wantInsecure)
			}
		})
	}
}
