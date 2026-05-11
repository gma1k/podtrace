package agent

import (
	"fmt"

	"github.com/podtrace/podtrace/pkg/tracer"
)

// newZipkinEventExporter does not implement direct export to Zipkin's
// native /api/v2/spans endpoint and intentionally returns a clear,
// user-actionable error.
func newZipkinEventExporter(_ CRKey, _ *BundlePayload) (tracer.Exporter, error) {
	return nil, fmt.Errorf(
		"zipkin: direct export is not supported (the OTel SDK Zipkin exporter is deprecated); " +
			"run an OpenTelemetry Collector with the 'zipkin' exporter and point podtrace at " +
			"the Collector via 'type: otlp' instead",
	)
}