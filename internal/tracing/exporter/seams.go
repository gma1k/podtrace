package exporter

import (
	"encoding/json"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
)

var (
	marshalJSON   = json.Marshal
	newOTLPClient = otlptracehttp.New
	newResource   = resource.New
)
