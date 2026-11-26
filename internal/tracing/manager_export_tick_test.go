package tracing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/config"
)

func TestExportTickTimeoutCoversAFewRequestsAndAtLeastAnInterval(t *testing.T) {
	saved := config.TracingExporterTimeout
	t.Cleanup(func() { config.TracingExporterTimeout = saved })

	config.TracingExporterTimeout = 10 * time.Second
	m := &Manager{exportInterval: 5 * time.Second}
	if got := m.exportTickTimeout(); got != 30*time.Second {
		t.Fatalf("exportTickTimeout = %s, want 30s", got)
	}
	m.exportInterval = time.Minute
	if got := m.exportTickTimeout(); got != time.Minute {
		t.Fatalf("exportTickTimeout = %s, want the 1m interval", got)
	}
}

func TestAnExportTickStopsAtItsDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(150 * time.Millisecond):
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	m := managerWithOnly(t, func() { config.ZipkinEndpoint = srv.URL })
	m.exportInterval = 0
	for _, id := range []string{"01", "02", "03", "04", "05", "06", "07", "08"} {
		trackSpan(m, "aabbccddeeff00112233445566778"+id+"0", "11223344556677"+id)
	}
	saved := config.TracingExporterTimeout
	t.Cleanup(func() { config.TracingExporterTimeout = saved })
	config.TracingExporterTimeout = 100 * time.Millisecond

	start := time.Now()
	m.exportTick(context.Background())

	if took := time.Since(start); took > time.Second {
		t.Fatalf("the export tick took %s with a 300ms deadline", took)
	}
	if pending := m.traceTracker.SnapshotForExport(0, true, "zipkin"); len(pending) != 8 {
		t.Fatalf("%d traces pending, want all 8 offered again", len(pending))
	}
}
