package exporter

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gma1k/podtrace/internal/diagnose/tracker"
)

func recordPostPath(t *testing.T) (*httptest.Server, func() string) {
	t.Helper()
	var mu sync.Mutex
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPath = r.URL.Path
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, func() string {
		mu.Lock()
		defer mu.Unlock()
		return gotPath
	}
}

func TestOTLPExporter_PostsToTracesPath(t *testing.T) {
	cases := []struct {
		name     string
		endpoint func(base string) string
		want     string
	}{
		{"base-url-without-path", func(base string) string { return base }, "/v1/traces"},
		{"base-url-with-trailing-slash", func(base string) string { return base + "/" }, "/v1/traces"},
		{"explicit-traces-path-preserved", func(base string) string { return base + "/v1/traces" }, "/v1/traces"},
		{"custom-path-preserved", func(base string) string { return base + "/otlp/v1/traces" }, "/otlp/v1/traces"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, postPath := recordPostPath(t)

			exporter, err := NewOTLPExporter(tc.endpoint(srv.URL), 1.0)
			if err != nil {
				t.Fatalf("NewOTLPExporter() error: %v", err)
			}
			t.Cleanup(func() { _ = exporter.Shutdown(t.Context()) })

			if err := exporter.ExportTraces([]*tracker.Trace{newTestTrace()}); err != nil {
				t.Fatalf("ExportTraces() error: %v", err)
			}
			if got := postPath(); got != tc.want {
				t.Errorf("POST path = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNewOTLPExporter_EndpointCarriesTracesPath(t *testing.T) {
	exporter, err := NewOTLPExporter("http://localhost:4318", 1.0)
	if err != nil {
		t.Fatalf("NewOTLPExporter() error: %v", err)
	}
	t.Cleanup(func() { _ = exporter.Shutdown(t.Context()) })

	if exporter.endpoint != "http://localhost:4318/v1/traces" {
		t.Errorf("endpoint = %q, want the OTLP traces path appended", exporter.endpoint)
	}
}
