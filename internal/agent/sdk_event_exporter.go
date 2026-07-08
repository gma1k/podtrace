package agent

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/logger"
	"github.com/podtrace/podtrace/internal/safeconv"
	"github.com/podtrace/podtrace/internal/tracing/extractor"
	bundlepkg "github.com/podtrace/podtrace/pkg/exporter/bundle"
	"github.com/podtrace/podtrace/pkg/tracer"
)

// sdkEventExporter is the shared event→span runtime used by every
// agent-side tracer.Exporter that emits OpenTelemetry SDK spans
// (OTLP, Jaeger via OTLP, Zipkin, DataDog, Splunk).
type sdkEventExporter struct {
	name       string
	cr         CRKey
	tp         *sdktrace.TracerProvider
	thresholds *PolicyThresholds
	metrics    *Metrics
	extractor  *extractor.HTTPExtractor
}

type sdkOption func(*sdkOptions)

type sdkOptions struct {
	metrics *Metrics
}

func withMetrics(m *Metrics) sdkOption {
	return func(o *sdkOptions) { o.metrics = m }
}

// newSDKEventExporter wires an SDK SpanExporter (the wire-format
// adapter, OTLP, Zipkin, etc.) into a TracerProvider shaped to the
// bundle's sampling, resource attribution, and batch settings, then
// returns a tracer.Exporter that emits one span per event.
func newSDKEventExporter(name string, cr CRKey, b *BundlePayload, spanExporter sdktrace.SpanExporter, opts ...sdkOption) (tracer.Exporter, error) {
	var cfg sdkOptions
	for _, opt := range opts {
		opt(&cfg)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sampler := sdktrace.AlwaysSample()
	if b.Sample != nil && *b.Sample < 1 {
		// An explicit 0 means "export nothing" — TraceIDRatioBased(0)
		// never samples, which is exactly the user's request.
		sampler = sdktrace.TraceIDRatioBased(*b.Sample)
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

	observed := &deliveryObservingExporter{
		inner:   spanExporter,
		cr:      cr,
		name:    name,
		metrics: cfg.metrics,
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(observed,
			sdktrace.WithMaxExportBatchSize(128),
			sdktrace.WithBatchTimeout(2*time.Second),
		),
		sdktrace.WithSampler(sampler),
		sdktrace.WithResource(res),
	)

	exp := &sdkEventExporter{
		name:      fmt.Sprintf("%s/%s", name, cr.String()),
		cr:        cr,
		tp:        tp,
		metrics:   cfg.metrics,
		extractor: extractor.NewHTTPExtractor(),
	}
	if b != nil && !b.Thresholds.IsZero() {
		exp.thresholds = policyThresholdsFromBundle(b.Thresholds)
	}
	if cfg.metrics != nil {
		cfg.metrics.ObserveEffectiveSampleRate(cr, b)
	}
	return exp, nil
}

// policyThresholdsFromBundle deep-copies the bundle's Thresholds into
// the agent-side struct. Decoupling the typed reference here means the
// SDK exporter is never holding a pointer into a BundlePayload that may
// be reused by a later reconcile.
func policyThresholdsFromBundle(in *bundleThresholds) *PolicyThresholds {
	if in == nil {
		return nil
	}
	out := &PolicyThresholds{}
	if in.ErrorRatePercent != nil {
		v := *in.ErrorRatePercent
		out.ErrorRatePercent = &v
	}
	if in.RTTSpikeMs != nil {
		v := *in.RTTSpikeMs
		out.RTTSpikeMs = &v
	}
	if in.FSSlowMs != nil {
		v := *in.FSSlowMs
		out.FSSlowMs = &v
	}
	return out
}

// bundleThresholds aliases the bundle package's Thresholds so the SDK
// exporter does not need to import that package directly (it already
// reaches it through BundlePayload).
type bundleThresholds = bundlepkg.Thresholds

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
		var startedAt time.Time
		if ev.Timestamp == 0 {
			startedAt = time.Now()
		} else {
			startedAt = ev.TimestampTime()
		}
		endedAt := startedAt.Add(time.Duration(safeUint64ToInt64(ev.LatencyNS)))
		if endedAt.Before(startedAt) {
			endedAt = startedAt
		}

		spanCtx := ctx
		if parent, ok := e.remoteParent(ev); ok {
			spanCtx = trace.ContextWithSpanContext(ctx, parent)
		}
		_, span := tr.Start(spanCtx, eventSpanName(ev), trace.WithTimestamp(startedAt))
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
		if ev.Type == events.EventHTTPReq || ev.Type == events.EventHTTPResp {
			attrs = append(attrs,
				attribute.String("http.scheme", ev.HTTPScheme()),
				attribute.String("podtrace.http.transport", ev.HTTPProtoLabel()),
			)
		}
		if ev.PeerDstIP != "" {
			attrs = append(attrs,
				attribute.String("network.peer.address", ev.PeerDstIP),
				attribute.Int("network.peer.port", int(ev.PeerDstPort)),
			)
		}
		if ev.PeerSrcIP != "" {
			attrs = append(attrs,
				attribute.String("network.local.address", ev.PeerSrcIP),
				attribute.Int("network.local.port", int(ev.PeerSrcPort)),
			)
		}
		attrs = appendK8sAttributes(attrs, ev.K8s)
		attrs = e.appendThresholdAttributes(attrs, ev)
		span.SetAttributes(attrs...)
		span.End(trace.WithTimestamp(endedAt))
	}
	return nil
}

// remoteParent derives the application span this event should hang under,
// from W3C/B3 trace context.
func (e *sdkEventExporter) remoteParent(ev *events.Event) (trace.SpanContext, bool) {
	traceIDHex, parentSpanHex := ev.TraceID, ev.ParentSpanID
	sampled := ev.TraceFlags&0x01 == 1
	if traceIDHex == "" && (ev.Type == events.EventHTTPReq || ev.Type == events.EventHTTPResp) && ev.Details != "" && e.extractor != nil {
		tc := e.extractor.ExtractFromRawHeaders(ev.Details)
		if tc == nil || !tc.HasRemoteParent() {
			return trace.SpanContext{}, false
		}
		traceIDHex, parentSpanHex, sampled = tc.TraceID, tc.ParentSpanID, tc.IsSampled()
	}
	if traceIDHex == "" || parentSpanHex == "" {
		return trace.SpanContext{}, false
	}
	tid, err := trace.TraceIDFromHex(traceIDHex)
	if err != nil {
		return trace.SpanContext{}, false
	}
	sid, err := trace.SpanIDFromHex(parentSpanHex)
	if err != nil {
		return trace.SpanContext{}, false
	}
	var flags trace.TraceFlags
	if sampled {
		flags = trace.FlagsSampled
	}
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    tid,
		SpanID:     sid,
		TraceFlags: flags,
		Remote:     true,
	})
	return sc, sc.IsValid()
}

// appendThresholdAttributes evaluates the bundle's thresholds against
// one event and, for each one tripped, stamps a span attribute and
// bumps the corresponding Prometheus counter.
// Threshold semantics (per design):
//   - fs_slow:    LatencyNS > FSSlowMs       for EventOpen/Read/Write/Fsync/Unlink/Rename/Close
//   - rtt_spike:  LatencyNS > RTTSpikeMs     for EventTCPRecv/TCPSend/Connect
//   - error_rate: ev.Error != 0              for any event (counts contribute to a future
//     rolling-window detector; the per-event tag is
//     stamped only when the threshold itself is set,
//     so users can grep their backend for "errors
//     sampled under an active error_rate policy")
func (e *sdkEventExporter) appendThresholdAttributes(attrs []attribute.KeyValue, ev *events.Event) []attribute.KeyValue {
	t := e.thresholds
	if t == nil {
		return attrs
	}
	if t.FSSlowMs != nil && isFilesystemEvent(ev.Type) {
		thresholdNs := safeconv.Int64ToUint64(int64(*t.FSSlowMs)) * uint64(config.NSPerMS)
		if ev.LatencyNS > thresholdNs {
			attrs = append(attrs,
				attribute.Bool("podtrace.threshold.fs_slow.tripped", true),
				attribute.Int64("podtrace.threshold.fs_slow.ms", int64(*t.FSSlowMs)),
			)
			e.recordTrip("fs_slow")
		}
	}
	if t.RTTSpikeMs != nil && isNetworkLatencyEvent(ev.Type) {
		thresholdNs := safeconv.Int64ToUint64(int64(*t.RTTSpikeMs)) * uint64(config.NSPerMS)
		if ev.LatencyNS > thresholdNs {
			attrs = append(attrs,
				attribute.Bool("podtrace.threshold.rtt_spike.tripped", true),
				attribute.Int64("podtrace.threshold.rtt_spike.ms", int64(*t.RTTSpikeMs)),
			)
			e.recordTrip("rtt_spike")
		}
	}
	if t.ErrorRatePercent != nil {
		isErr := ev.Error != 0
		if isErr {
			attrs = append(attrs,
				attribute.Bool("podtrace.threshold.error_rate.observed", true),
				attribute.Int64("podtrace.threshold.error_rate.percent", int64(*t.ErrorRatePercent)),
			)
			e.recordTrip("error_rate")
		}
		if e.metrics != nil {
			if justBreached := e.metrics.ObserveErrorRate(e.cr, *t.ErrorRatePercent, isErr); justBreached {
				attrs = append(attrs,
					attribute.Bool("podtrace.threshold.error_rate.breached", true),
				)
			}
		}
	}
	return attrs
}

func (e *sdkEventExporter) recordTrip(kind string) {
	if e.metrics == nil {
		return
	}
	e.metrics.RecordThresholdTripped(e.cr, kind)
}

// isFilesystemEvent reports whether the event type is one the FS-slow
// threshold should be evaluated against.
func isFilesystemEvent(t events.EventType) bool {
	switch t {
	case events.EventOpen, events.EventClose, events.EventRead,
		events.EventWrite, events.EventFsync, events.EventUnlink, events.EventRename:
		return true
	default:
		return false
	}
}

// isNetworkLatencyEvent reports whether the event type carries a
// meaningful latency the RTT-spike threshold should be evaluated against.
func isNetworkLatencyEvent(t events.EventType) bool {
	switch t {
	case events.EventConnect, events.EventTCPSend, events.EventTCPRecv,
		events.EventUDPSend, events.EventUDPRecv:
		return true
	default:
		return false
	}
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

// deliveryObservingExporter wraps an SDK SpanExporter to make export
// (delivery) failures observable.
type deliveryObservingExporter struct {
	inner   sdktrace.SpanExporter
	cr      CRKey
	name    string
	metrics *Metrics

	mu      sync.Mutex
	failing bool
}

func (e *deliveryObservingExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	err := e.inner.ExportSpans(ctx, spans)
	if err != nil {
		e.metrics.ObserveExportDelivery(e.cr, len(spans), err)
		e.mu.Lock()
		firstFailure := !e.failing
		e.failing = true
		e.mu.Unlock()
		if firstFailure {
			logger.Warn("exporter delivery failing: spans are being captured but NOT reaching the backend; "+
				"check the ExporterConfig endpoint/credentials and that the collector is reachable",
				zap.String("cr", e.cr.String()),
				zap.String("exporter", e.name),
				zap.Int("spans_dropped", len(spans)),
				zap.Error(err))
		}
		return err
	}
	e.mu.Lock()
	recovered := e.failing
	e.failing = false
	e.mu.Unlock()
	if recovered {
		logger.Info("exporter delivery recovered",
			zap.String("cr", e.cr.String()), zap.String("exporter", e.name))
	}
	return nil
}

func (e *deliveryObservingExporter) Shutdown(ctx context.Context) error {
	return e.inner.Shutdown(ctx)
}

var _ sdktrace.SpanExporter = (*deliveryObservingExporter)(nil)
