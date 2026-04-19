package exporter

import (
	"context"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/diagnose/tracker"
	"github.com/podtrace/podtrace/internal/events"
)

func TestNewDataDogExporter(t *testing.T) {
	exporter, err := NewDataDogExporter("", "", 1.0)
	if err != nil {
		t.Fatalf("NewDataDogExporter() error = %v", err)
	}
	if exporter == nil {
		t.Fatal("NewDataDogExporter() returned nil")
	}
	if exporter.endpoint != config.DefaultDataDogEndpoint {
		t.Errorf("Expected endpoint %s, got %s", config.DefaultDataDogEndpoint, exporter.endpoint)
	}
}

func TestNewDataDogExporter_WithAPIKey(t *testing.T) {
	exporter, err := NewDataDogExporter("http://localhost:8126/v0.4/traces", "my-api-key", 1.0)
	if err != nil {
		t.Fatalf("NewDataDogExporter() error = %v", err)
	}
	if exporter.apiKey != "my-api-key" {
		t.Errorf("Expected apiKey 'my-api-key', got '%s'", exporter.apiKey)
	}
}

func TestDataDogExporter_ExportTraces_Disabled(t *testing.T) {
	exporter := &DataDogExporter{enabled: false}
	err := exporter.ExportTraces([]*tracker.Trace{})
	if err != nil {
		t.Errorf("ExportTraces() error = %v", err)
	}
}

func TestDataDogExporter_ExportTraces_Empty(t *testing.T) {
	exporter := &DataDogExporter{enabled: true}
	err := exporter.ExportTraces([]*tracker.Trace{})
	if err != nil {
		t.Errorf("ExportTraces() error = %v", err)
	}
}

func TestDataDogExporter_shouldSample(t *testing.T) {
	tests := []struct {
		name       string
		sampleRate float64
	}{
		{"rate 1.0", 1.0},
		{"rate 0.0", 0.0},
		{"rate 0.5", 0.5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := &DataDogExporter{sampleRate: tt.sampleRate}
			trace := &tracker.Trace{TraceID: "test"}
			result := exporter.shouldSample(trace)
			if tt.sampleRate == 1.0 && !result {
				t.Error("Sample rate 1.0 should always sample")
			}
			if tt.sampleRate == 0.0 && result {
				t.Error("Sample rate 0.0 should never sample")
			}
		})
	}
}

func TestDataDogExporter_exportTrace_NoSpans(t *testing.T) {
	exporter := &DataDogExporter{enabled: true}
	trace := &tracker.Trace{
		TraceID: "test",
		Spans:   []*tracker.Span{},
	}
	err := exporter.exportTrace(trace)
	if err != nil {
		t.Errorf("exportTrace() error = %v", err)
	}
}

func TestDataDogExporter_exportTrace_WithSpans(t *testing.T) {
	exporter, err := NewDataDogExporter("http://localhost:8126/v0.4/traces", "", 1.0)
	if err != nil {
		t.Fatalf("NewDataDogExporter() error = %v", err)
	}
	trace := &tracker.Trace{
		TraceID: "aabbccddeeff00112233445566778899",
		Spans: []*tracker.Span{
			{
				TraceID:   "aabbccddeeff00112233445566778899",
				SpanID:    "1122334455667788",
				Operation: "test-op",
				Service:   "test-service",
				StartTime: time.Now(),
				Duration:  100 * time.Millisecond,
				Events: []*events.Event{
					{
						Type:      events.EventHTTPReq,
						Target:    "http://example.com",
						Timestamp: uint64(time.Now().UnixNano()),
						LatencyNS: 500000,
					},
				},
			},
		},
	}
	exportErr := exporter.exportTrace(trace)
	if exportErr != nil {
		t.Logf("exportTrace() error (expected for test without server): %v", exportErr)
	}
}

func TestDataDogExporter_exportTrace_WithErrorSpan(t *testing.T) {
	exporter, err := NewDataDogExporter("http://localhost:8126/v0.4/traces", "", 1.0)
	if err != nil {
		t.Fatalf("NewDataDogExporter() error = %v", err)
	}
	trace := &tracker.Trace{
		TraceID: "aabbccddeeff00112233445566778899",
		Spans: []*tracker.Span{
			{
				TraceID:    "aabbccddeeff00112233445566778899",
				SpanID:     "1122334455667788",
				Operation:  "test-op",
				Service:    "test-service",
				StartTime:  time.Now(),
				Duration:   100 * time.Millisecond,
				Error:      true,
				Attributes: map[string]string{"http.status_code": "500"},
			},
		},
	}
	exportErr := exporter.exportTrace(trace)
	if exportErr != nil {
		t.Logf("exportTrace() error (expected for test without server): %v", exportErr)
	}
}

func TestDataDogExporter_exportTrace_WithParentSpanID(t *testing.T) {
	exporter, err := NewDataDogExporter("http://localhost:8126/v0.4/traces", "", 1.0)
	if err != nil {
		t.Fatalf("NewDataDogExporter() error = %v", err)
	}
	trace := &tracker.Trace{
		TraceID: "aabbccddeeff00112233445566778899",
		Spans: []*tracker.Span{
			{
				TraceID:      "aabbccddeeff00112233445566778899",
				SpanID:       "1122334455667788",
				ParentSpanID: "aabbccddeeff0011",
				Operation:    "child-op",
				Service:      "test-service",
				StartTime:    time.Now(),
				Duration:     50 * time.Millisecond,
			},
		},
	}
	exportErr := exporter.exportTrace(trace)
	if exportErr != nil {
		t.Logf("exportTrace() error (expected for test without server): %v", exportErr)
	}
}

func TestDataDogExporter_exportTrace_WithEmptyServiceName(t *testing.T) {
	exporter, err := NewDataDogExporter("http://localhost:8126/v0.4/traces", "", 1.0)
	if err != nil {
		t.Fatalf("NewDataDogExporter() error = %v", err)
	}
	trace := &tracker.Trace{
		TraceID: "aabbccddeeff00112233445566778899",
		Spans: []*tracker.Span{
			{
				TraceID:   "aabbccddeeff00112233445566778899",
				SpanID:    "1122334455667788",
				Operation: "test-op",
				Service:   "",
				StartTime: time.Now(),
				Duration:  100 * time.Millisecond,
			},
		},
	}
	exportErr := exporter.exportTrace(trace)
	if exportErr != nil {
		t.Logf("exportTrace() error (expected for test without server): %v", exportErr)
	}
}

func TestDataDogExporter_ExportTraces_WithSampledTrace(t *testing.T) {
	exporter, err := NewDataDogExporter("http://localhost:8126/v0.4/traces", "", 1.0)
	if err != nil {
		t.Fatalf("NewDataDogExporter() error = %v", err)
	}
	trace := &tracker.Trace{
		TraceID: "aabbccddeeff00112233445566778899",
		Spans: []*tracker.Span{
			{
				TraceID:   "aabbccddeeff00112233445566778899",
				SpanID:    "1122334455667788",
				Operation: "test-op",
				Service:   "test-service",
				StartTime: time.Now(),
				Duration:  100 * time.Millisecond,
			},
		},
	}
	err = exporter.ExportTraces([]*tracker.Trace{trace})
	if err != nil {
		t.Logf("ExportTraces() error (expected for test without server): %v", err)
	}
}

func TestDataDogExporter_ExportTraces_WithNotSampledTrace(t *testing.T) {
	exporter, err := NewDataDogExporter("http://localhost:8126/v0.4/traces", "", 0.0)
	if err != nil {
		t.Fatalf("NewDataDogExporter() error = %v", err)
	}
	trace := &tracker.Trace{
		TraceID: "aabbccddeeff00112233445566778899",
		Spans: []*tracker.Span{
			{
				TraceID:   "aabbccddeeff00112233445566778899",
				SpanID:    "1122334455667788",
				Operation: "test-op",
				Service:   "test-service",
				StartTime: time.Now(),
				Duration:  100 * time.Millisecond,
			},
		},
	}
	err = exporter.ExportTraces([]*tracker.Trace{trace})
	if err != nil {
		t.Errorf("ExportTraces() error = %v", err)
	}
}

func TestDataDogExporter_Shutdown(t *testing.T) {
	exporter := &DataDogExporter{}
	ctx := context.Background()
	err := exporter.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}
}

func TestHexToUint64(t *testing.T) {
	tests := []struct {
		input    string
		expected uint64
	}{
		{"", 0},
		{"0000000000000001", 1},
		{"aabbccddeeff0011", 0xaabbccddeeff0011},
		{"aabbccddeeff00112233445566778899", 0x2233445566778899}, // takes lower 16 chars
		{"invalid", 0},
	}

	for _, tt := range tests {
		got := hexToUint64(tt.input)
		if got != tt.expected {
			t.Errorf("hexToUint64(%q) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

func TestSpanType(t *testing.T) {
	tests := []struct {
		name     string
		events   []*events.Event
		expected string
	}{
		{
			name:     "no events",
			events:   nil,
			expected: "custom",
		},
		{
			name:     "HTTP event",
			events:   []*events.Event{{Type: events.EventHTTPReq}},
			expected: "web",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			span := &tracker.Span{Events: tt.events}
			got := spanType(span)
			if got != tt.expected {
				t.Errorf("spanType() = %q, want %q", got, tt.expected)
			}
		})
	}
}
