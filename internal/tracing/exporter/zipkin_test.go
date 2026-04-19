package exporter

import (
	"context"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/diagnose/tracker"
	"github.com/podtrace/podtrace/internal/events"
)

func TestNewZipkinExporter(t *testing.T) {
	exporter, err := NewZipkinExporter("", 1.0)
	if err != nil {
		t.Fatalf("NewZipkinExporter() error = %v", err)
	}
	if exporter == nil {
		t.Fatal("NewZipkinExporter() returned nil")
	}
	if exporter.endpoint != config.DefaultZipkinEndpoint {
		t.Errorf("Expected endpoint %s, got %s", config.DefaultZipkinEndpoint, exporter.endpoint)
	}
}

func TestZipkinExporter_ExportTraces_Disabled(t *testing.T) {
	exporter := &ZipkinExporter{enabled: false}
	err := exporter.ExportTraces([]*tracker.Trace{})
	if err != nil {
		t.Errorf("ExportTraces() error = %v", err)
	}
}

func TestZipkinExporter_ExportTraces_Empty(t *testing.T) {
	exporter := &ZipkinExporter{enabled: true}
	err := exporter.ExportTraces([]*tracker.Trace{})
	if err != nil {
		t.Errorf("ExportTraces() error = %v", err)
	}
}

func TestZipkinExporter_shouldSample(t *testing.T) {
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
			exporter := &ZipkinExporter{sampleRate: tt.sampleRate}
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

func TestZipkinExporter_exportTrace_NoSpans(t *testing.T) {
	exporter := &ZipkinExporter{enabled: true}
	trace := &tracker.Trace{
		TraceID: "test",
		Spans:   []*tracker.Span{},
	}
	err := exporter.exportTrace(trace)
	if err != nil {
		t.Errorf("exportTrace() error = %v", err)
	}
}

func TestZipkinExporter_exportTrace_WithSpans(t *testing.T) {
	exporter, err := NewZipkinExporter("http://localhost:9411/api/v2/spans", 1.0)
	if err != nil {
		t.Fatalf("NewZipkinExporter() error = %v", err)
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

func TestZipkinExporter_exportTrace_WithErrorSpan(t *testing.T) {
	exporter, err := NewZipkinExporter("http://localhost:9411/api/v2/spans", 1.0)
	if err != nil {
		t.Fatalf("NewZipkinExporter() error = %v", err)
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

func TestZipkinExporter_exportTrace_WithParentSpanID(t *testing.T) {
	exporter, err := NewZipkinExporter("http://localhost:9411/api/v2/spans", 1.0)
	if err != nil {
		t.Fatalf("NewZipkinExporter() error = %v", err)
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

func TestZipkinExporter_exportTrace_WithEmptyServiceName(t *testing.T) {
	exporter, err := NewZipkinExporter("http://localhost:9411/api/v2/spans", 1.0)
	if err != nil {
		t.Fatalf("NewZipkinExporter() error = %v", err)
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

func TestZipkinExporter_ExportTraces_WithSampledTrace(t *testing.T) {
	exporter, err := NewZipkinExporter("http://localhost:9411/api/v2/spans", 1.0)
	if err != nil {
		t.Fatalf("NewZipkinExporter() error = %v", err)
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

func TestZipkinExporter_ExportTraces_WithNotSampledTrace(t *testing.T) {
	exporter, err := NewZipkinExporter("http://localhost:9411/api/v2/spans", 0.0)
	if err != nil {
		t.Fatalf("NewZipkinExporter() error = %v", err)
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

func TestZipkinExporter_Shutdown(t *testing.T) {
	exporter := &ZipkinExporter{}
	ctx := context.Background()
	err := exporter.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}
}

func TestZipkinKind(t *testing.T) {
	tests := []struct {
		name     string
		events   []*events.Event
		expected string
	}{
		{
			name:     "no events",
			events:   nil,
			expected: "",
		},
		{
			name:     "HTTP event",
			events:   []*events.Event{{Type: events.EventHTTPReq}},
			expected: "CLIENT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			span := &tracker.Span{Events: tt.events}
			got := zipkinKind(span)
			if got != tt.expected {
				t.Errorf("zipkinKind() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestMax64(t *testing.T) {
	if max64(5, 3) != 5 {
		t.Error("max64(5,3) should return 5")
	}
	if max64(1, 10) != 10 {
		t.Error("max64(1,10) should return 10")
	}
	if max64(0, 1) != 1 {
		t.Error("max64(0,1) should return 1")
	}
}
