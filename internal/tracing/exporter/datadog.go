package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/diagnose/tracker"
)

type DataDogExporter struct {
	endpoint   string
	apiKey     string
	client     *http.Client
	enabled    bool
	sampleRate float64
}

// DataDog v0.4 trace format: outer array = list of traces, inner array = spans of one trace.
type datadogSpan struct {
	TraceID  uint64            `json:"trace_id"`
	SpanID   uint64            `json:"span_id"`
	ParentID uint64            `json:"parent_id"`
	Name     string            `json:"name"`
	Resource string            `json:"resource"`
	Service  string            `json:"service"`
	Type     string            `json:"type"`
	Start    int64             `json:"start"`
	Duration int64             `json:"duration"`
	Error    int32             `json:"error"`
	Meta     map[string]string `json:"meta"`
	Metrics  map[string]float64 `json:"metrics"`
}

func NewDataDogExporter(endpoint, apiKey string, sampleRate float64) (*DataDogExporter, error) {
	if endpoint == "" {
		endpoint = config.DefaultDataDogEndpoint
	}

	return &DataDogExporter{
		endpoint:   endpoint,
		apiKey:     apiKey,
		client:     &http.Client{Timeout: config.TracingExporterTimeout},
		enabled:    true,
		sampleRate: sampleRate,
	}, nil
}

func (e *DataDogExporter) ExportTraces(traces []*tracker.Trace) error {
	if !e.enabled || len(traces) == 0 {
		return nil
	}

	for _, t := range traces {
		if !e.shouldSample(t) {
			continue
		}

		if err := e.exportTrace(t); err != nil {
			continue
		}
	}

	return nil
}

func (e *DataDogExporter) shouldSample(_ *tracker.Trace) bool {
	if e.sampleRate >= 1.0 {
		return true
	}
	if e.sampleRate <= 0.0 {
		return false
	}
	return time.Now().UnixNano()%int64(1.0/e.sampleRate) == 0
}

func (e *DataDogExporter) exportTrace(t *tracker.Trace) error {
	if len(t.Spans) == 0 {
		return nil
	}

	ddSpans := make([]datadogSpan, 0, len(t.Spans))

	for _, span := range t.Spans {
		span.UpdateDuration()

		serviceName := span.Service
		if serviceName == "" {
			serviceName = "unknown"
		}

		ddSpan := datadogSpan{
			TraceID:  hexToUint64(span.TraceID),
			SpanID:   hexToUint64(span.SpanID),
			ParentID: hexToUint64(span.ParentSpanID),
			Name:     span.Operation,
			Resource: span.Operation,
			Service:  serviceName,
			Type:     spanType(span),
			Start:    span.StartTime.UnixNano(),
			Duration: span.Duration.Nanoseconds(),
			Meta:     make(map[string]string),
			Metrics:  make(map[string]float64),
		}

		if span.Error {
			ddSpan.Error = 1
		}

		for k, v := range span.Attributes {
			ddSpan.Meta[k] = v
		}

		for _, event := range span.Events {
			ddSpan.Meta["event."+event.TypeString()] = event.Target
			ddSpan.Metrics["latency_ns."+event.TypeString()] = float64(event.LatencyNS)
		}

		ddSpans = append(ddSpans, ddSpan)
	}

	// v0.4 payload: array of traces, each trace is an array of spans.
	payload, err := json.Marshal([][]datadogSpan{ddSpans})
	if err != nil {
		return fmt.Errorf("failed to marshal datadog payload: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), "POST", e.endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if e.apiKey != "" {
		req.Header.Set("DD-API-KEY", e.apiKey)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

func (e *DataDogExporter) Shutdown(ctx context.Context) error {
	return nil
}

// hexToUint64 converts a hex trace/span ID string to uint64 (takes lower 64 bits for 128-bit IDs).
func hexToUint64(s string) uint64 {
	if s == "" {
		return 0
	}
	if len(s) > 16 {
		s = s[len(s)-16:]
	}
	v, _ := strconv.ParseUint(s, 16, 64)
	return v
}

// spanType returns the DataDog span type based on the span's events.
func spanType(span *tracker.Span) string {
	for _, event := range span.Events {
		switch event.TypeString() {
		case "HTTP":
			return "web"
		case "DB":
			return "db"
		case "Redis", "Memcached":
			return "cache"
		case "gRPC":
			return "rpc"
		}
	}
	return "custom"
}
