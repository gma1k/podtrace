package agent

import (
	"github.com/podtrace/podtrace/pkg/tracer"
)

// newSplunkEventExporter builds a tracer.Exporter that ships per-event
// spans to Splunk Observability Cloud via OTLP HTTP.
func newSplunkEventExporter(cr CRKey, b *BundlePayload) (tracer.Exporter, error) {
	spanExporter, err := newOTLPSpanExporter(b)
	if err != nil {
		return nil, err
	}
	return newSDKEventExporter("splunk", cr, b, spanExporter)
}