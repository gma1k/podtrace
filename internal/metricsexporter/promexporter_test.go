package metricsexporter

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

func TestExportMetricsHelpers(t *testing.T) {
	e := &events.Event{
		Type:        events.EventDNS,
		ProcessName: "testproc",
		LatencyNS:   uint64(time.Millisecond * 50),
		Bytes:       1024,
	}

	ExportRTTMetric(e)
	ExportTCPMetric(e)
	ExportDNSMetric(e)
	ExportFileSystemMetric(e)
	ExportSchedSwitchMetric(e)
	ExportNetworkBandwidthMetric(e, "send")
	ExportFilesystemBandwidthMetric(e, "write")
}

func TestSecurityAndRateLimitMiddleware(t *testing.T) {
	hit := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
	})

	handler := securityHeadersMiddleware(rateLimitMiddleware(next))

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !hit {
		t.Fatalf("expected inner handler to be called")
	}

	res := w.Result()
	if res.Header.Get("X-Content-Type-Options") == "" {
		t.Fatalf("expected security headers to be set")
	}
}

func TestStartServerAndShutdown(t *testing.T) {
	t.Setenv("PODTRACE_METRICS_ADDR", "127.0.0.1:0")
	t.Setenv("PODTRACE_METRICS_INSECURE_ALLOW_ANY_ADDR", "1")

	srv := StartServer()
	if srv == nil {
		t.Fatalf("expected non-nil server")
	}

	done := make(chan struct{})
	go func() {
		time.Sleep(100 * time.Millisecond)
		srv.Shutdown()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("server did not shut down in time")
	}

	os.Unsetenv("PODTRACE_METRICS_ADDR")
	os.Unsetenv("PODTRACE_METRICS_INSECURE_ALLOW_ANY_ADDR")
}
