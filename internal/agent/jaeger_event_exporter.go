package agent

import (
	"github.com/podtrace/podtrace/pkg/tracer"
)

// newJaegerEventExporter builds a tracer.Exporter that ships per-event
// spans to a Jaeger collector via OTLP HTTP.
//
// Bundle expectations:
//   - Endpoint  — Jaeger's OTLP HTTP receiver, default port 4318
//                 (e.g. "jaeger-collector.observability:4318").
//   - Insecure  — typically true for in-cluster collectors.
//   - Sample    — honored via sdkEventExporter's sampler.
func newJaegerEventExporter(cr CRKey, b *BundlePayload, opts ...sdkOption) (tracer.Exporter, error) {
	spanExporter, err := newOTLPSpanExporter(b)
	if err != nil {
		return nil, err
	}
	return newSDKEventExporter("jaeger", cr, b, spanExporter, opts...)
}