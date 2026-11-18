package main

import (
	"testing"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/tracing/exporter"
	"github.com/gma1k/podtrace/pkg/exporter/bundle"
)

func TestAnInsecureExporterConfigReachesACleartextCollector(t *testing.T) {
	defer resetTracingConfig()
	t.Setenv("PODTRACE_OTLP_INSECURE", "")
	mustApplyPayload(t, &bundle.Payload{Type: bundle.TypeOTLP, Endpoint: "otel.observability:4318", Insecure: true})

	if _, err := exporter.NewOTLPExporter(config.OTLPEndpoint, 1); err != nil {
		t.Fatalf("insecure: true must let the session export over http, got %v", err)
	}
}

func TestASecureExporterConfigDoesNotInheritAnEarlierOptIn(t *testing.T) {
	defer resetTracingConfig()
	t.Setenv("PODTRACE_OTLP_INSECURE", "")
	config.OTLPInsecure = true
	config.ExporterInsecure = true
	mustApplyPayload(t, &bundle.Payload{Type: bundle.TypeOTLP, Endpoint: "otel.observability:4318"})

	if config.OTLPInsecure || config.ExporterInsecure {
		t.Fatal("a bundle that asks for TLS inherited an earlier cleartext opt-in")
	}
	if config.OTLPEndpoint != "https://otel.observability:4318" {
		t.Fatalf("OTLPEndpoint = %q, want https", config.OTLPEndpoint)
	}
}

func TestAnExplicitHTTPEndpointReachesItsCollectorLikeTheAgent(t *testing.T) {
	defer resetTracingConfig()
	t.Setenv("PODTRACE_OTLP_INSECURE", "")
	mustApplyPayload(t, &bundle.Payload{Type: bundle.TypeOTLP, Endpoint: "http://otel.observability:4318"})

	if _, err := exporter.NewOTLPExporter(config.OTLPEndpoint, 1); err != nil {
		t.Fatalf("an ExporterConfig naming http:// must export over http, got %v", err)
	}
}

func TestPayloadAllowsCleartext(t *testing.T) {
	cases := []struct {
		name string
		p    bundle.Payload
		want bool
	}{
		{"otlp insecure", bundle.Payload{Type: bundle.TypeOTLP, Endpoint: "otel:4318", Insecure: true}, true},
		{"otlp schemeless", bundle.Payload{Type: bundle.TypeOTLP, Endpoint: "otel:4318"}, false},
		{"otlp https", bundle.Payload{Type: bundle.TypeOTLP, Endpoint: "https://otel:4318"}, false},
		{"otlp http", bundle.Payload{Type: bundle.TypeOTLP, Endpoint: " HTTP://otel:4318"}, true},
		{"splunk schemeless", bundle.Payload{Type: bundle.TypeSplunk, Endpoint: "ingest.example.com"}, false},
		{"datadog http", bundle.Payload{Type: bundle.TypeDataDog, Endpoint: "http://datadog-agent:4318"}, true},
		{"jaeger schemeless", bundle.Payload{Type: bundle.TypeJaeger, Endpoint: "jaeger:14268"}, true},
		{"jaeger https", bundle.Payload{Type: bundle.TypeJaeger, Endpoint: "https://jaeger:4318"}, false},
		{"zipkin schemeless", bundle.Payload{Type: bundle.TypeZipkin, Endpoint: "zipkin:9411"}, true},
		{"zipkin https", bundle.Payload{Type: bundle.TypeZipkin, Endpoint: "https://zipkin:9411"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := payloadAllowsCleartext(&tc.p); got != tc.want {
				t.Fatalf("payloadAllowsCleartext = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestASchemelessJaegerOrZipkinSessionStillExportsWithoutTheJobEnv(t *testing.T) {
	defer resetTracingConfig()
	t.Setenv("PODTRACE_OTLP_INSECURE", "")
	t.Setenv("PODTRACE_EXPORTER_INSECURE", "")

	mustApplyPayload(t, &bundle.Payload{Type: bundle.TypeJaeger, Endpoint: "jaeger-collector.observability:14268"})
	if _, err := exporter.NewJaegerExporter(config.JaegerEndpoint, 1); err != nil {
		t.Fatalf("jaeger: %v", err)
	}

	mustApplyPayload(t, &bundle.Payload{Type: bundle.TypeZipkin, Endpoint: "zipkin.observability:9411"})
	if _, err := exporter.NewZipkinExporter(config.ZipkinEndpoint, 1); err != nil {
		t.Fatalf("zipkin: %v", err)
	}
}

func TestAnHTTPSZipkinBundleDoesNotOptIntoCleartext(t *testing.T) {
	defer resetTracingConfig()
	config.ExporterInsecure = true
	mustApplyPayload(t, &bundle.Payload{Type: bundle.TypeZipkin, Endpoint: "https://zipkin:9411"})
	if config.ExporterInsecure {
		t.Fatal("an https Zipkin bundle kept an earlier cleartext opt-in")
	}
}

func TestADataDogBundleWithoutAHeaderNameUsesTheAgentConvention(t *testing.T) {
	defer resetTracingConfig()
	mustApplyPayload(t, &bundle.Payload{Type: bundle.TypeDataDog, Endpoint: "datadog-agent:4318", Credential: []byte("k")})

	if config.OTLPHeaders["DD-API-KEY"] != "k" {
		t.Fatalf("OTLPHeaders = %v, want DD-API-KEY", config.OTLPHeaders)
	}
}

func TestAZipkinBundleKeepsTheNativeExporter(t *testing.T) {
	defer resetTracingConfig()
	mustApplyPayload(t, &bundle.Payload{Type: bundle.TypeZipkin, Endpoint: "http://zipkin:9411/api/v2/spans"})

	if config.ZipkinEndpoint != "http://zipkin:9411/api/v2/spans" || config.OTLPEndpoint != "" {
		t.Fatalf("Zipkin=%q OTLP=%q", config.ZipkinEndpoint, config.OTLPEndpoint)
	}
}
