package exporter

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
)

func TestExportTrace_MarshalError(t *testing.T) {
	orig := marshalJSON
	marshalJSON = func(any) ([]byte, error) { return nil, errors.New("boom") }
	defer func() { marshalJSON = orig }()

	dd, err := NewDataDogExporter("https://collector.example.com", "k", 1.0)
	if err != nil {
		t.Fatal(err)
	}
	if err := dd.exportTrace(newTestTrace()); err == nil || !strings.Contains(err.Error(), "marshal") {
		t.Errorf("datadog exportTrace: err=%v, want marshal error", err)
	}

	sp, err := NewSplunkExporter("https://collector.example.com", "tok", 1.0)
	if err != nil {
		t.Fatal(err)
	}
	if err := sp.sendBatch(sp.buildEvents(newTestTrace())); err == nil || !strings.Contains(err.Error(), "marshal") {
		t.Errorf("splunk sendBatch: err=%v, want marshal error", err)
	}

	zp, err := NewZipkinExporter("https://collector.example.com", 1.0)
	if err != nil {
		t.Fatal(err)
	}
	if err := zp.exportTrace(newTestTrace()); err == nil || !strings.Contains(err.Error(), "marshal") {
		t.Errorf("zipkin exportTrace: err=%v, want marshal error", err)
	}
}

func TestNewOTLPExporter_ConstructorErrors(t *testing.T) {
	origClient := newOTLPClient
	origResource := newResource
	defer func() {
		newOTLPClient = origClient
		newResource = origResource
	}()

	newOTLPClient = func(context.Context, ...otlptracehttp.Option) (*otlptrace.Exporter, error) {
		return nil, errors.New("boom client")
	}
	if _, err := NewOTLPExporter("https://collector.example.com", 1.0); err == nil || !strings.Contains(err.Error(), "OTLP exporter") {
		t.Errorf("client constructor: err=%v, want OTLP exporter error", err)
	}

	newOTLPClient = origClient
	newResource = func(context.Context, ...resource.Option) (*resource.Resource, error) {
		return nil, errors.New("boom resource")
	}
	if _, err := NewOTLPExporter("https://collector.example.com", 1.0); err == nil || !strings.Contains(err.Error(), "resource") {
		t.Errorf("resource constructor: err=%v, want resource error", err)
	}
}
