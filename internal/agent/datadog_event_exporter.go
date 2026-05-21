package agent

import (
	"github.com/podtrace/podtrace/pkg/tracer"
)

// newDataDogEventExporter builds a tracer.Exporter that ships per-event
// spans to DataDog via OTLP HTTP. DataDog supports OTLP through two
// supported paths and the agent works with both:
func newDataDogEventExporter(cr CRKey, b *BundlePayload, opts ...sdkOption) (tracer.Exporter, error) {
	spanExporter, err := newOTLPSpanExporter(b)
	if err != nil {
		return nil, err
	}
	return newSDKEventExporter("datadog", cr, b, spanExporter, opts...)
}