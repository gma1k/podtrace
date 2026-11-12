package tracing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/config"
)

func hangingServer(t *testing.T) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})
	return srv
}

func TestAHangingCollectorDoesNotDelayTheOtherExporters(t *testing.T) {
	hanging := hangingServer(t)
	var zipkinAt atomic.Int64
	zipkin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		zipkinAt.CompareAndSwap(0, time.Now().UnixNano())
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(zipkin.Close)
	m := managerWithOnly(t, func() {
		config.DataDogEndpoint = hanging.URL
		config.ZipkinEndpoint = zipkin.URL
	})
	trackSpan(m, "aabbccddeeff00112233445566778899", "1122334455667788")

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	m.exportTraces(ctx, true)

	at := zipkinAt.Load()
	if at == 0 {
		t.Fatal("zipkin never received the trace")
	}
	if waited := time.Duration(at - start.UnixNano()); waited > 750*time.Millisecond {
		t.Fatalf("zipkin waited %s behind the hanging datadog collector", waited)
	}
	status := map[string]ExporterStatus{}
	for _, st := range m.ExportStatus() {
		status[st.Exporter] = st
	}
	if status["zipkin"].SucceededBatches != 1 || status["datadog"].FailedBatches != 1 {
		t.Fatalf("export status = %+v, want zipkin delivered and datadog failed", status)
	}
}

func TestFlushReturnsAtItsDeadlineWhenTheCollectorHangs(t *testing.T) {
	hanging := hangingServer(t)
	m := managerWithOnly(t, func() { config.ZipkinEndpoint = hanging.URL })
	trackSpan(m, "aabbccddeeff00112233445566778899", "1122334455667788")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	m.Flush(ctx)

	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("Flush took %s with a 200ms deadline", took)
	}
	traces := m.traceTracker.SnapshotForExport(0, true, "zipkin")
	if len(traces) != 1 {
		t.Fatalf("the trace cut off by the deadline must be offered again; %d pending", len(traces))
	}
}

func TestShutdownAbortsAnExportInFlight(t *testing.T) {
	hanging := hangingServer(t)
	m := managerWithOnly(t, func() { config.ZipkinEndpoint = hanging.URL })
	m.exportInterval = 10 * time.Millisecond
	trackSpan(m, "aabbccddeeff00112233445566778899", "1122334455667788")
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = m.Shutdown(ctx)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the export loop kept waiting on the hanging collector after Shutdown")
	}
}
