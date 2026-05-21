package agent

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/pkg/tracer"
)

// sdkEventExporter is the shared event→span runtime used by every
// agent-side tracer.Exporter that emits OpenTelemetry SDK spans
// (OTLP, Jaeger via OTLP, Zipkin, DataDog, Splunk).
type sdkEventExporter struct {
	name string
	tp   *sdktrace.TracerProvider
}

// newSDKEventExporter wires an SDK SpanExporter (the wire-format
// adapter — OTLP, Zipkin, etc.) into a TracerProvider shaped to the
// bundle's sampling, resource attribution, and batch settings, then
// returns a tracer.Exporter that emits one span per event.
func newSDKEventExporter(name string, cr CRKey, b *BundlePayload, spanExporter sdktrace.SpanExporter) (tracer.Exporter, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sampler := sdktrace.AlwaysSample()
	if b.Sample > 0 && b.Sample < 1 {
		sampler = sdktrace.TraceIDRatioBased(b.Sample)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName("podtrace"),
			attribute.String("podtrace.cr.namespace", cr.Namespace),
			attribute.String("podtrace.cr.name", cr.Name),
			attribute.String("podtrace.exporter", name),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("build resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(spanExporter,
			sdktrace.WithMaxExportBatchSize(128),
			sdktrace.WithBatchTimeout(2*time.Second),
		),
		sdktrace.WithSampler(sampler),
		sdktrace.WithResource(res),
	)

	return &sdkEventExporter{
		name: fmt.Sprintf("%s/%s", name, cr.String()),
		tp:   tp,
	}, nil
}

func (e *sdkEventExporter) Name() string { return e.name }

// Export creates one span per event. This is a lossy compression of
// the semantic trace graph a full Tracker would assemble, but it
// faithfully captures "this event happened at this time with these
// attributes" — enough for the agent's routing guarantees to be
// observable in any OTel-aware backend.
func (e *sdkEventExporter) Export(ctx context.Context, batch []*events.Event) error {
	if len(batch) == 0 {
		return nil
	}
	tr := e.tp.Tracer("podtrace.io/agent")
	for _, ev := range batch {
		if ev == nil {
			continue
		}
		startedAt := time.Unix(0, safeUint64ToInt64(ev.Timestamp))
		if startedAt.IsZero() {
			startedAt = time.Now()
		}
		endedAt := startedAt.Add(time.Duration(safeUint64ToInt64(ev.LatencyNS)))
		if endedAt.Before(startedAt) {
			endedAt = startedAt
		}

		_, span := tr.Start(ctx, eventSpanName(ev), trace.WithTimestamp(startedAt))
		attrs := []attribute.KeyValue{
			attribute.String("podtrace.event.type", eventTypeString(ev.Type)),
			attribute.Int64("podtrace.event.pid", int64(ev.PID)),
			attribute.Int64("podtrace.event.cgroup_id", safeUint64ToInt64(ev.CgroupID)),
			attribute.String("podtrace.event.process", ev.ProcessName),
			attribute.String("podtrace.event.target", ev.Target),
			attribute.Int64("podtrace.event.bytes", safeUint64ToInt64(ev.Bytes)),
			attribute.Int64("podtrace.event.latency_ns", safeUint64ToInt64(ev.LatencyNS)),
			attribute.Int("podtrace.event.error", int(ev.Error)),
		}
		attrs = appendK8sAttributes(attrs, ev.K8s)
		span.SetAttributes(attrs...)
		span.End(trace.WithTimestamp(endedAt))
	}
	return nil
}

func (e *sdkEventExporter) Close(ctx context.Context) error {
	if e.tp == nil {
		return nil
	}
	flushCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_ = e.tp.ForceFlush(flushCtx)
	return e.tp.Shutdown(ctx)
}

var _ tracer.Exporter = (*sdkEventExporter)(nil)