package exporter

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/diagnose/tracker"
)

type OTLPExporter struct {
	exporter   sdktrace.SpanExporter
	tracer     trace.Tracer
	tp         *sdktrace.TracerProvider
	endpoint   string
	enabled    bool
	sampleRate float64
}

func isLoopbackHost(host string) bool {
	h := strings.ToLower(host)
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// normalizeOTLPHTTPEndpoint returns a full URL for WithEndpointURL and whether to use WithInsecure (HTTP).
func normalizeOTLPHTTPEndpoint(endpoint string) (endpointURL string, useInsecure bool, err error) {
	raw := strings.TrimSpace(endpoint)
	if raw == "" {
		raw = config.DefaultOTLPEndpoint
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false, fmt.Errorf("parse OTLP endpoint: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		u, err = url.Parse("http://" + raw)
		if err != nil {
			return "", false, fmt.Errorf("parse OTLP endpoint: %w", err)
		}
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false, fmt.Errorf("otlp endpoint scheme must be http or https")
	}
	host := u.Hostname()
	if u.Scheme == "http" {
		if isLoopbackHost(host) || config.OTLPAllowInsecureNonLoopback() {
			return u.String(), true, nil
		}
		return "", false, fmt.Errorf("otlp: refusing cleartext http to %q; use https:// or set PODTRACE_OTLP_INSECURE=1", host)
	}
	return u.String(), false, nil
}

func NewOTLPExporter(endpoint string, sampleRate float64) (*OTLPExporter, error) {
	endpointURL, useInsecure, err := normalizeOTLPHTTPEndpoint(endpoint)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpointURL(endpointURL),
		otlptracehttp.WithTimeout(config.TracingExporterTimeout),
	}
	if useInsecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	otlpExporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String("Podtrace"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(otlpExporter),
		sdktrace.WithResource(res),
	)

	otel.SetTracerProvider(tp)

	return &OTLPExporter{
		exporter:   otlpExporter,
		tp:         tp,
		tracer:     tp.Tracer("Podtrace"),
		endpoint:   endpointURL,
		enabled:    true,
		sampleRate: sampleRate,
	}, nil
}

func (e *OTLPExporter) ExportTraces(traces []*tracker.Trace) error {
	if !e.enabled || len(traces) == 0 {
		return nil
	}

	ctx := context.Background()
	for _, t := range traces {
		if !e.shouldSample(t) {
			continue
		}

		for _, span := range t.Spans {
			if err := e.exportSpan(ctx, span, t); err != nil {
				continue
			}
		}
	}

	return nil
}

func (e *OTLPExporter) shouldSample(_ *tracker.Trace) bool {
	if e.sampleRate >= 1.0 {
		return true
	}
	if e.sampleRate <= 0.0 {
		return false
	}
	return time.Now().UnixNano()%int64(1.0/e.sampleRate) == 0
}

func (e *OTLPExporter) exportSpan(ctx context.Context, span *tracker.Span, _ *tracker.Trace) error {
	span.UpdateDuration()

	traceID, err := trace.TraceIDFromHex(span.TraceID)
	if err != nil {
		return fmt.Errorf("invalid trace ID: %w", err)
	}

	spanID, err := trace.SpanIDFromHex(span.SpanID)
	if err != nil {
		return fmt.Errorf("invalid span ID: %w", err)
	}

	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		Remote:     false,
		TraceFlags: trace.FlagsSampled,
	})

	ctx = trace.ContextWithSpanContext(ctx, spanContext)

	_, otelSpan := e.tracer.Start(ctx, span.Operation,
		trace.WithTimestamp(span.StartTime),
	)

	attrs := make([]attribute.KeyValue, 0, len(span.Attributes))
	for k, v := range span.Attributes {
		attrs = append(attrs, attribute.String(k, v))
	}
	if span.ParentSpanID != "" {
		attrs = append(attrs, attribute.String("parent_span_id", span.ParentSpanID))
	}
	otelSpan.SetAttributes(attrs...)

	if span.Error {
		otelSpan.RecordError(fmt.Errorf("span error"))
	}

	for _, event := range span.Events {
		otelSpan.AddEvent(event.TypeString(),
			trace.WithTimestamp(event.TimestampTime()),
			trace.WithAttributes(
				attribute.String("target", event.Target),
				attribute.Int64("latency_ns", int64(event.LatencyNS)),
			),
		)
	}

	otelSpan.End(trace.WithTimestamp(span.StartTime.Add(span.Duration)))

	return nil
}

func (e *OTLPExporter) Shutdown(ctx context.Context) error {
	if e.tp != nil {
		return e.tp.Shutdown(ctx)
	}
	return nil
}
