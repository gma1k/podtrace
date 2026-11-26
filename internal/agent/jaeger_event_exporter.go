package agent

import (
	"github.com/gma1k/podtrace/pkg/tracer"
)

// newJaegerEventExporter builds a tracer.Exporter that ships per-event
// spans to a Jaeger collector via OTLP HTTP.
//
// Bundle expectations:
//   - Endpoint  — Jaeger's OTLP HTTP receiver, default port 4318
//     (e.g. "jaeger-collector.observability:4318"). Without a scheme it is
//     reached the way session Jobs reach it (bundle.SchemelessCleartext):
//     over http, unless the exporter sends headers.
//   - Sample    — honored via sdkEventExporter's sampler.
func newJaegerEventExporter(cr CRKey, b *BundlePayload, opts ...sdkOption) (tracer.Exporter, error) {
	transport := *b
	transport.Insecure = b.SchemelessCleartext()
	spanExporter, err := newOTLPSpanExporter(&transport)
	if err != nil {
		return nil, err
	}
	return newSDKEventExporter("jaeger", cr, b, spanExporter, opts...)
}
