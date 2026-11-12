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

// splunkMaxBatchBytes bounds a single HEC request body so a large export is
// split into a few sized requests rather than one unbounded POST (or, as
// before, one POST per span).
const splunkMaxBatchBytes = 512 * 1024

type SplunkExporter struct {
	endpoint   string
	token      string
	client     *http.Client
	enabled    bool
	sampleRate float64
}

type SplunkEvent struct {
	Time       int64                  `json:"time"`
	Host       string                 `json:"host,omitempty"`
	Source     string                 `json:"source,omitempty"`
	Sourcetype string                 `json:"sourcetype,omitempty"`
	Event      map[string]interface{} `json:"event"`
}

func NewSplunkExporter(endpoint, token string, sampleRate float64) (*SplunkExporter, error) {
	endpoint, err := validateExporterEndpoint(endpoint, config.DefaultSplunkEndpoint)
	if err != nil {
		return nil, fmt.Errorf("splunk: %w", err)
	}

	return &SplunkExporter{
		endpoint:   endpoint,
		token:      token,
		client:     netguard.HardenedClient(config.TracingExporterTimeout),
		enabled:    true,
		sampleRate: sampleRate,
	}, nil
}

func (e *SplunkExporter) ExportTraces(traces []*tracker.Trace) error {
	return e.ExportTracesContext(context.Background(), traces)
}

// ExportTracesContext delivers the sampled traces as HEC batches: event
// JSON objects concatenated into one request body (the format Splunk HEC
// accepts), each body bounded by splunkMaxBatchBytes. When a trace's events
// straddle a failed request, only the events not yet delivered are offered
// again. ctx bounds the whole export.
func (e *SplunkExporter) ExportTracesContext(ctx context.Context, traces []*tracker.Trace) error {
	if !e.enabled || len(traces) == 0 {
		return nil
	}

	var outcome exportOutcome
	encoded := make([]encodedTrace, 0, len(traces))
	for _, t := range traces {
		if !e.shouldSample(t) || len(t.Spans) == 0 {
			continue
		}
		elements, err := encodeSpans(e.buildEvents(t))
		if err != nil {
			outcome.record(permanent(fmt.Errorf("trace %s: marshal event: %w", t.TraceID, err)))
			continue
		}
		encoded = append(encoded, encodedTrace{traceID: t.TraceID, elements: elements})
	}
	sendTraceBatches(ctx, &outcome, encoded, splunkMaxBatchBytes, hecFrame, e.postBatch)
	return outcome.err()
}

func (e *SplunkExporter) shouldSample(t *tracker.Trace) bool {
	return sampleTrace(t.TraceID, e.sampleRate)
}

func (e *SplunkExporter) buildEvents(t *tracker.Trace) []SplunkEvent {
	events := make([]SplunkEvent, 0, len(t.Spans))
	for _, span := range t.Spans {
		span.UpdateDuration()

		eventData := map[string]interface{}{
			"trace_id":       span.TraceID,
			"span_id":        span.SpanID,
			"parent_span_id": span.ParentSpanID,
			"operation":      span.Operation,
			"service":        span.Service,
			"start_time":     span.StartTime.Unix(),
			"duration_ms":    span.Duration.Milliseconds(),
			"span_count":     len(span.Events),
		}

		for k, v := range span.Attributes {
			eventData[k] = v
		}

		if span.Error {
			eventData["error"] = true
		}

		events = append(events, SplunkEvent{
			Time:       span.StartTime.Unix(),
			Sourcetype: "Podtrace:trace",
			Event:      eventData,
		})
	}
	return events
}

func (e *SplunkExporter) postBatch(ctx context.Context, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, "POST", e.endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if e.token != "" {
		req.Header.Set("Authorization", "Splunk "+e.token)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return statusError(resp.StatusCode)
	}
	return nil
}

func (e *SplunkExporter) Shutdown(ctx context.Context) error {
	return nil
}
