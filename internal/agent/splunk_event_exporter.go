package agent

import (
	"fmt"

	"github.com/gma1k/podtrace/pkg/tracer"
)

// newSplunkEventExporter builds a tracer.Exporter that ships per-event
// spans to Splunk Observability Cloud via OTLP HTTP.
func newSplunkEventExporter(cr CRKey, b *BundlePayload, opts ...sdkOption) (tracer.Exporter, error) {
	spanExporter, err := newOTLPSpanExporter(b)
	if err != nil {
		return nil, err
	}
	if len(b.Credential) == 0 {
		return nil, fmt.Errorf("splunk exporter: missing token")
	}
	return newSDKEventExporter("splunk", cr, b, spanExporter, opts...)
}
