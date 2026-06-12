package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/diagnose/tracker"
)

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
	if endpoint == "" {
		endpoint = config.DefaultSplunkEndpoint
	}

	return &SplunkExporter{
		endpoint:   endpoint,
		token:      token,
		client:     &http.Client{Timeout: config.TracingExporterTimeout},
		enabled:    true,
		sampleRate: sampleRate,
	}, nil
}

func (e *SplunkExporter) ExportTraces(traces []*tracker.Trace) error {
	if !e.enabled || len(traces) == 0 {
		return nil
	}

	var errs []error
	for _, t := range traces {
		if !e.shouldSample(t) {
			continue
		}

		if err := e.exportTrace(t); err != nil {
			errs = append(errs, fmt.Errorf("trace %s: %w", t.TraceID, err))
		}
	}

	return errors.Join(errs...)
}

func (e *SplunkExporter) shouldSample(t *tracker.Trace) bool {
	return sampleTrace(t.TraceID, e.sampleRate)
}

func (e *SplunkExporter) exportTrace(t *tracker.Trace) error {
	if len(t.Spans) == 0 {
		return nil
	}

	events := make([]SplunkEvent, 0)

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

		event := SplunkEvent{
			Time:       span.StartTime.Unix(),
			Sourcetype: "Podtrace:trace",
			Event:      eventData,
		}

		events = append(events, event)
	}

	var errs []error
	for _, event := range events {
		payload, err := json.Marshal(event)
		if err != nil {
			errs = append(errs, fmt.Errorf("marshal event: %w", err))
			continue
		}

		req, err := http.NewRequestWithContext(context.Background(), "POST", e.endpoint, bytes.NewReader(payload))
		if err != nil {
			errs = append(errs, fmt.Errorf("create request: %w", err))
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		if e.token != "" {
			req.Header.Set("Authorization", "Splunk "+e.token)
		}

		resp, err := e.client.Do(req)
		if err != nil {
			errs = append(errs, fmt.Errorf("send request: %w", err))
			continue
		}
		_ = resp.Body.Close()
		// HEC failures (401 bad token, 400 malformed event) used to be
		// indistinguishable from success.
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
			errs = append(errs, fmt.Errorf("unexpected status code: %d", resp.StatusCode))
		}
	}

	return errors.Join(errs...)
}

func (e *SplunkExporter) Shutdown(ctx context.Context) error {
	return nil
}
