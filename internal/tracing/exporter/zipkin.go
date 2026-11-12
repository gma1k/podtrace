package exporter

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/diagnose/tracker"
	"github.com/gma1k/podtrace/internal/netguard"
)

type ZipkinExporter struct {
	endpoint   string
	client     *http.Client
	enabled    bool
	sampleRate float64
}

// Zipkin v2 span format.
type zipkinSpan struct {
	TraceID       string             `json:"traceId"`
	ID            string             `json:"id"`
	ParentID      string             `json:"parentId,omitempty"`
	Name          string             `json:"name"`
	Timestamp     int64              `json:"timestamp"`
	Duration      int64              `json:"duration"`
	Kind          string             `json:"kind,omitempty"`
	LocalEndpoint zipkinEndpoint     `json:"localEndpoint"`
	Tags          map[string]string  `json:"tags,omitempty"`
	Annotations   []zipkinAnnotation `json:"annotations,omitempty"`
}

type zipkinEndpoint struct {
	ServiceName string `json:"serviceName"`
}

type zipkinAnnotation struct {
	Timestamp int64  `json:"timestamp"`
	Value     string `json:"value"`
}

func NewZipkinExporter(endpoint string, sampleRate float64) (*ZipkinExporter, error) {
	endpoint, err := validateExporterEndpoint(endpoint, config.DefaultZipkinEndpoint)
	if err != nil {
		return nil, fmt.Errorf("zipkin: %w", err)
	}

	return &ZipkinExporter{
		endpoint:   endpoint,
		client:     netguard.HardenedClient(config.TracingExporterTimeout),
		enabled:    true,
		sampleRate: sampleRate,
	}, nil
}

func (e *ZipkinExporter) ExportTraces(traces []*tracker.Trace) error {
	return e.ExportTracesContext(context.Background(), traces)
}

// ExportTracesContext sends the sampled traces as size-bounded Zipkin v2
// span arrays; ctx bounds the whole export.
func (e *ZipkinExporter) ExportTracesContext(ctx context.Context, traces []*tracker.Trace) error {
	if !e.enabled || len(traces) == 0 {
		return nil
	}

	var outcome exportOutcome
	encoded := make([]encodedTrace, 0, len(traces))
	for _, t := range traces {
		if !e.shouldSample(t) || len(t.Spans) == 0 {
			continue
		}
		elements, err := encodeSpans(zipkinSpans(t))
		if err != nil {
			outcome.record(permanent(fmt.Errorf("trace %s: failed to marshal zipkin payload: %w", t.TraceID, err)))
			continue
		}
		encoded = append(encoded, encodedTrace{traceID: t.TraceID, elements: elements})
	}
	sendTraceBatches(ctx, &outcome, encoded, maxBatchBytes, jsonArrayFrame, e.post)
	return outcome.err()
}

func (e *ZipkinExporter) shouldSample(t *tracker.Trace) bool {
	return sampleTrace(t.TraceID, e.sampleRate)
}

func zipkinSpans(t *tracker.Trace) []zipkinSpan {
	out := make([]zipkinSpan, 0, len(t.Spans))
	for _, span := range t.Spans {
		span.UpdateDuration()

		serviceName := span.Service
		if serviceName == "" {
			serviceName = "unknown"
		}

		zs := zipkinSpan{
			TraceID:   span.TraceID,
			ID:        span.SpanID,
			ParentID:  span.ParentSpanID,
			Name:      span.Operation,
			Timestamp: span.StartTime.UnixMicro(),
			Duration:  max64(span.Duration.Microseconds(), 1),
			Kind:      zipkinKind(span),
			LocalEndpoint: zipkinEndpoint{
				ServiceName: serviceName,
			},
			Tags:        make(map[string]string),
			Annotations: make([]zipkinAnnotation, 0, len(span.Events)),
		}

		for k, v := range span.Attributes {
			zs.Tags[k] = v
		}

		if span.Error {
			zs.Tags["error"] = "true"
		}

		for _, event := range span.Events {
			zs.Annotations = append(zs.Annotations, zipkinAnnotation{
				Timestamp: event.TimestampTime().UnixMicro(),
				Value:     fmt.Sprintf("%s %s latency=%dns", event.TypeString(), event.Target, event.LatencyNS),
			})
		}

		out = append(out, zs)
	}
	return out
}

func (e *ZipkinExporter) post(ctx context.Context, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, "POST", e.endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusNoContent {
		return statusError(resp.StatusCode)
	}

	return nil
}

func (e *ZipkinExporter) Shutdown(ctx context.Context) error {
	return nil
}

// zipkinKind maps span events to a Zipkin span kind (CLIENT/SERVER).
func zipkinKind(span *tracker.Span) string {
	for _, event := range span.Events {
		switch event.TypeString() {
		case "HTTP", "HTTPS", "HTTP/2", "HTTP/3", "DB", "CACHE", "gRPC":
			return "CLIENT"
		}
	}
	return ""
}

// max64 returns the larger of two int64 values.
func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
