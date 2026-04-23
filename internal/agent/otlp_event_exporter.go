package agent

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/pkg/tracer"
)

// otlpEventExporter emits one OTLP span per event. It is a deliberate
// simplification of the full Tracker+Span assembly pipeline: events
// are interesting on their own and the agent routing correctness test
// only needs proof that the right events reach the right exporter.
// Future phases can replace this with a per-CR Tracker that builds
// parent/child span trees, without changing the tracer.Exporter contract.
type otlpEventExporter struct {
	name         string
	tp           *sdktrace.TracerProvider
	tracerShared *sync.Once // guards setting the global tracer provider; we do not set it (CR exporters run in parallel)
}

// newOTLPEventExporter constructs the SDK exporter and provider from a
// BundlePayload. The returned exporter is namespaced by CR key so that
// log output, metrics, and errors are attributable to a single CR.
func newOTLPEventExporter(cr CRKey, b *BundlePayload) (tracer.Exporter, error) {
	if b.Endpoint == "" {
		return nil, fmt.Errorf("bundle missing endpoint")
	}

	endpoint, err := normalizeOTLPEndpoint(b.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("bundle endpoint: %w", err)
	}

	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(endpoint),
	}
	if b.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	if len(b.Headers) > 0 || b.HeaderName != "" {
		headers := map[string]string{}
		for k, v := range b.Headers {
			headers[k] = v
		}
		if b.HeaderName != "" && len(b.Credential) > 0 {
			headers[b.HeaderName] = string(b.Credential)
		}
		opts = append(opts, otlptracehttp.WithHeaders(headers))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := otlptracehttp.NewClient(opts...)
	spanExporter, err := otlptrace.New(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("create OTLP span exporter: %w", err)
	}

	sampler := sdktrace.AlwaysSample()
	if b.Sample > 0 && b.Sample < 1 {
		sampler = sdktrace.TraceIDRatioBased(b.Sample)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName("podtrace"),
			attribute.String("podtrace.cr.namespace", cr.Namespace),
			attribute.String("podtrace.cr.name", cr.Name),
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

	return &otlpEventExporter{
		name:         fmt.Sprintf("otlp/%s", cr.String()),
		tp:           tp,
		tracerShared: &sync.Once{},
	}, nil
}

func (e *otlpEventExporter) Name() string { return e.name }

// Export creates one span per event. This is a lossy compression of
// the semantic trace graph a full Tracker would assemble, but it
// faithfully captures "this event happened at this time with these
// attributes" — enough for the agent's routing guarantees to be
// observable in an OTLP backend.
func (e *otlpEventExporter) Export(ctx context.Context, batch []*events.Event) error {
	if len(batch) == 0 {
		return nil
	}
	tr := e.tp.Tracer("podtrace.io/agent")
	for _, ev := range batch {
		if ev == nil {
			continue
		}
		// Kernel-provided uint64 fields (timestamp, latency, cgroup ID,
		// byte counts) are narrowed to int64 via safeUint64ToInt64 to
		// avoid the silent wrap-to-negative that would otherwise
		// confuse any dashboard built against the OTel signed types.
		startedAt := time.Unix(0, safeUint64ToInt64(ev.Timestamp))
		if startedAt.IsZero() {
			startedAt = time.Now()
		}
		endedAt := startedAt.Add(time.Duration(safeUint64ToInt64(ev.LatencyNS)))
		if endedAt.Before(startedAt) {
			endedAt = startedAt
		}

		_, span := tr.Start(ctx, eventSpanName(ev), trace.WithTimestamp(startedAt))
		span.SetAttributes(
			attribute.String("podtrace.event.type", eventTypeString(ev.Type)),
			attribute.Int64("podtrace.event.pid", int64(ev.PID)),
			attribute.Int64("podtrace.event.cgroup_id", safeUint64ToInt64(ev.CgroupID)),
			attribute.String("podtrace.event.process", ev.ProcessName),
			attribute.String("podtrace.event.target", ev.Target),
			attribute.Int64("podtrace.event.bytes", safeUint64ToInt64(ev.Bytes)),
			attribute.Int64("podtrace.event.latency_ns", safeUint64ToInt64(ev.LatencyNS)),
			attribute.Int("podtrace.event.error", int(ev.Error)),
		)
		span.End(trace.WithTimestamp(endedAt))
	}
	return nil
}

// Close flushes any pending spans and shuts down the provider. Called
// once by the Router when the CR leaves the active set.
func (e *otlpEventExporter) Close(ctx context.Context) error {
	if e.tp == nil {
		return nil
	}
	// ForceFlush is best-effort: if the OTLP collector is unreachable
	// at shutdown we do not want to block process exit. Short timeout.
	flushCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_ = e.tp.ForceFlush(flushCtx)
	return e.tp.Shutdown(ctx)
}

// normalizeOTLPEndpoint strips any scheme because otlptracehttp takes
// a host:port (it adds scheme based on WithInsecure). Accepts both
// "collector:4318" and "http://collector:4318" forms for user convenience.
func normalizeOTLPEndpoint(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("empty endpoint")
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", err
		}
		return u.Host, nil
	}
	return raw, nil
}

// eventSpanName picks a human-readable span name from the event. Keep
// it short: trace backends index span-name heavily and verbose names
// balloon cardinality.
func eventSpanName(ev *events.Event) string {
	base := eventTypeString(ev.Type)
	if ev.Target != "" {
		return base + " " + ev.Target
	}
	return base
}

func eventTypeString(t events.EventType) string {
	if s, ok := eventTypeNames[t]; ok {
		return s
	}
	return fmt.Sprintf("event_%d", uint32(t))
}

// eventTypeNames maps the small set of EventType values we care about
// for span-name readability. Unmatched values fall back to the generic
// "event_<N>" in eventTypeString — we explicitly prefer this over
// dumping the bare int so span search queries remain legible.
var eventTypeNames = map[events.EventType]string{
	events.EventDNS:      "dns",
	events.EventConnect:  "net.connect",
	events.EventTCPSend:  "net.tcp.send",
	events.EventTCPRecv:  "net.tcp.recv",
	events.EventWrite:    "fs.write",
	events.EventRead:     "fs.read",
	events.EventOpen:     "fs.open",
	events.EventClose:    "fs.close",
	events.EventExec:     "proc.exec",
	events.EventFork:     "proc.fork",
	events.EventHTTPReq:  "http.req",
	events.EventHTTPResp: "http.resp",
	events.EventDBQuery:  "db.query",
}
