package exporter

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/diagnose/tracker"
	"github.com/podtrace/podtrace/internal/events"
)

func failingServer(status int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	}))
}

func errorSurfaceTrace() []*tracker.Trace {
	return []*tracker.Trace{{
		TraceID: "0123456789abcdef0123456789abcdef",
		Spans: []*tracker.Span{{
			TraceID:    "0123456789abcdef0123456789abcdef",
			SpanID:     "0123456789abcdef",
			Operation:  "HTTP",
			StartTime:  time.Now(),
			Attributes: map[string]string{},
			Events:     []*events.Event{{Type: events.EventHTTPReq}},
		}},
	}}
}

// TestExportTraces_SurfacesBackendFailures is a regression test: every
// exporter used to swallow per-trace errors and return nil, which made the
// manager's entire exporter-failure alerting layer unreachable dead code.
func TestExportTraces_SurfacesBackendFailures(t *testing.T) {
	srv := failingServer(http.StatusInternalServerError)
	defer srv.Close()

	traces := errorSurfaceTrace()

	jaeger := &JaegerExporter{enabled: true, endpoint: srv.URL, client: srv.Client(), sampleRate: 1.0}
	if err := jaeger.ExportTraces(traces); err == nil {
		t.Error("jaeger: expected an error for a 500 backend, got nil")
	}

	zipkin := &ZipkinExporter{enabled: true, endpoint: srv.URL, client: srv.Client(), sampleRate: 1.0}
	if err := zipkin.ExportTraces(traces); err == nil {
		t.Error("zipkin: expected an error for a 500 backend, got nil")
	}

	datadog := &DataDogExporter{enabled: true, endpoint: srv.URL, client: srv.Client(), sampleRate: 1.0}
	if err := datadog.ExportTraces(traces); err == nil {
		t.Error("datadog: expected an error for a 500 backend, got nil")
	}
}

// TestSplunkExportTraces_RejectsAuthFailure: Splunk never checked
// resp.StatusCode, so a 401 from a bad HEC token looked exactly like
// success.
func TestSplunkExportTraces_RejectsAuthFailure(t *testing.T) {
	srv := failingServer(http.StatusUnauthorized)
	defer srv.Close()

	splunk := &SplunkExporter{enabled: true, endpoint: srv.URL, token: "bad", client: srv.Client(), sampleRate: 1.0}
	if err := splunk.ExportTraces(errorSurfaceTrace()); err == nil {
		t.Error("splunk: expected an error for a 401 backend, got nil")
	}
}
