package tracing

import (
	"testing"

	"github.com/podtrace/podtrace/internal/alerting"
	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
)

// TestManager_ExportTraces_AllFiveExporters_Populated drives a populated batch
// through every configured exporter (OTLP, Jaeger, Splunk, DataDog, Zipkin) at
// sample rate 1.0, exercising each exporter's non-nil branch and the successful
// (err == nil) export path in a single deterministic pass.
func TestManager_ExportTraces_AllFiveExporters_Populated(t *testing.T) {
	originalOTLP := config.OTLPEndpoint
	originalJaeger := config.JaegerEndpoint
	originalSplunk := config.SplunkEndpoint
	originalDataDog := config.DataDogEndpoint
	originalZipkin := config.ZipkinEndpoint
	originalSampleRate := config.TracingSampleRate
	originalTracing := config.TracingEnabled
	originalAlerting := alerting.GetGlobalManager()

	config.TracingEnabled = true
	config.TracingSampleRate = 1.0
	config.OTLPEndpoint = "http://localhost:4317"
	config.JaegerEndpoint = "http://localhost:14268/api/traces"
	config.SplunkEndpoint = "http://localhost:8088/services/collector"
	config.DataDogEndpoint = "http://localhost:8126/v0.4/traces"
	config.ZipkinEndpoint = "http://localhost:9411/api/v2/spans"

	defer func() {
		config.OTLPEndpoint = originalOTLP
		config.JaegerEndpoint = originalJaeger
		config.SplunkEndpoint = originalSplunk
		config.DataDogEndpoint = originalDataDog
		config.ZipkinEndpoint = originalZipkin
		config.TracingSampleRate = originalSampleRate
		config.TracingEnabled = originalTracing
		alerting.SetGlobalManager(originalAlerting)
	}()

	alertManager, _ := alerting.NewManager()
	alerting.SetGlobalManager(alertManager)

	manager, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	if manager.otlpExporter == nil {
		t.Error("expected OTLP exporter to be constructed")
	}
	if manager.jaegerExporter == nil {
		t.Error("expected Jaeger exporter to be constructed")
	}
	if manager.splunkExporter == nil {
		t.Error("expected Splunk exporter to be constructed")
	}
	if manager.datadogExporter == nil {
		t.Error("expected DataDog exporter to be constructed")
	}
	if manager.zipkinExporter == nil {
		t.Error("expected Zipkin exporter to be constructed")
	}

	if manager.GetTraceCount() != 0 {
		t.Fatalf("expected empty tracker, got %d traces", manager.GetTraceCount())
	}
	manager.exportTraces()

	manager.traceTracker.ProcessEvent(&events.Event{
		Type:    events.EventHTTPReq,
		TraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:  "00f067aa0ba902b7",
	}, nil)

	if manager.GetTraceCount() == 0 {
		t.Fatalf("expected at least one trace after ProcessEvent")
	}

	manager.exportTraces()
}
