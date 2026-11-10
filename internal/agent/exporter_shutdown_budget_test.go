package agent

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/pkg/tracer"
)

func withShutdownBudget(t *testing.T, d time.Duration) {
	t.Helper()
	saved := exporterShutdownBudget
	exporterShutdownBudget = d
	t.Cleanup(func() { exporterShutdownBudget = saved })
}

func TestSDKEventExporter_CloseAgainstBlackholedCollectorIsBounded(t *testing.T) {
	withShutdownBudget(t, 300*time.Millisecond)

	var started, finished atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		started.Add(1)
		<-r.Context().Done()
		finished.Add(1)
	}))
	defer srv.Close()

	exp, err := newOTLPEventExporter(CRKey{"ns", "blackholed"}, &BundlePayload{
		Type: "otlp", Endpoint: strings.TrimPrefix(srv.URL, "http://"), Insecure: true,
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	now := uint64(time.Now().UnixNano())
	batch := make([]*events.Event, 0, 1000)
	for i := 0; i < 1000; i++ {
		batch = append(batch, &events.Event{Type: events.EventOpen, Timestamp: now, Target: "/f"})
	}
	if err := exp.Export(context.Background(), batch); err != nil {
		t.Fatalf("Export: %v", err)
	}

	begin := time.Now()
	_ = exp.Close(context.Background())
	if elapsed := time.Since(begin); elapsed > 3*time.Second {
		t.Fatalf("Close took %s against a blackholed collector, want about the shutdown budget", elapsed)
	}

	deadline := time.Now().Add(3 * time.Second)
	for finished.Load() < started.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if finished.Load() != started.Load() {
		t.Fatalf("in-flight export not cancelled after Close: started %d, finished %d", started.Load(), finished.Load())
	}
	settled := started.Load()
	time.Sleep(500 * time.Millisecond)
	if got := started.Load(); got != settled {
		t.Errorf("drain kept sending after Close gave up: %d requests, then %d", settled, got)
	}
}

func TestSDKEventExporter_CloseStillFlushesAHealthyCollector(t *testing.T) {
	cs := newCaptureServer()
	defer cs.close()

	exp, err := newOTLPEventExporter(CRKey{"ns", "healthy"}, &BundlePayload{Type: "otlp", Endpoint: cs.endpointHostPort(), Insecure: true})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	now := uint64(time.Now().UnixNano())
	batch := make([]*events.Event, 0, 300)
	for i := 0; i < 300; i++ {
		batch = append(batch, &events.Event{Type: events.EventOpen, Timestamp: now, Target: "/f"})
	}
	if err := exp.Export(context.Background(), batch); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if err := exp.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := cs.hitCount(); got < 3 {
		t.Errorf("collector received %d requests, want every 128-span batch flushed", got)
	}
}

type slowClosingExporter struct {
	delay  time.Duration
	closed atomic.Bool
	budget atomic.Int64
}

func (e *slowClosingExporter) Name() string                                  { return "slow" }
func (e *slowClosingExporter) Export(context.Context, []*events.Event) error { return nil }
func (e *slowClosingExporter) Close(ctx context.Context) error {
	if deadline, ok := ctx.Deadline(); ok {
		e.budget.Store(int64(time.Until(deadline)))
	}
	select {
	case <-time.After(e.delay):
	case <-ctx.Done():
	}
	e.closed.Store(true)
	return nil
}

var _ tracer.Exporter = (*slowClosingExporter)(nil)

func TestRouterClose_ClosesExportersInParallel(t *testing.T) {
	r := NewRouter(nil)
	exporters := make([]*slowClosingExporter, 4)
	rules := make([]CRRule, 0, len(exporters))
	for i := range exporters {
		exporters[i] = &slowClosingExporter{delay: 300 * time.Millisecond}
		rules = append(rules, CRRule{Key: CRKey{Namespace: "ns", Name: string(rune('a' + i))}, Exporter: exporters[i]})
	}
	r.Publish(rules)

	begin := time.Now()
	if err := r.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if elapsed := time.Since(begin); elapsed > 900*time.Millisecond {
		t.Errorf("Router.Close took %s for 4 exporters of 300ms each, want them closed in parallel", elapsed)
	}
	for i, e := range exporters {
		if !e.closed.Load() {
			t.Errorf("exporter %d not closed", i)
		}
	}
}

func TestCloseDisplacedExporters_ClosesInParallelEachWithItsOwnBudget(t *testing.T) {
	exporters := []*slowClosingExporter{{delay: 300 * time.Millisecond}, {delay: 300 * time.Millisecond}, {delay: 300 * time.Millisecond}}
	r := &AgentReconciler{}
	for _, e := range exporters {
		r.pendingClose = append(r.pendingClose, e)
	}
	begin := time.Now()
	r.closeDisplacedExporters()

	var wg sync.WaitGroup
	for _, e := range exporters {
		wg.Add(1)
		go func(e *slowClosingExporter) {
			defer wg.Done()
			for !e.closed.Load() && time.Since(begin) < 3*time.Second {
				time.Sleep(5 * time.Millisecond)
			}
		}(e)
	}
	wg.Wait()
	if elapsed := time.Since(begin); elapsed > 700*time.Millisecond {
		t.Errorf("3 displaced exporters of 300ms each took %s to close, want them closed in parallel", elapsed)
	}
	for i, e := range exporters {
		if !e.closed.Load() {
			t.Fatalf("displaced exporter %d not closed", i)
		}
		if got := time.Duration(e.budget.Load()); got < exporterCloseTimeout-time.Second {
			t.Errorf("displaced exporter %d got %s to close, want its own %s", i, got, exporterCloseTimeout)
		}
	}
}

func TestSDKEventExporter_ZeroValueBudgetFallsBackToTheDefault(t *testing.T) {
	e := &sdkEventExporter{tp: sdktrace.NewTracerProvider()}
	if err := e.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

type countingShutdownExporter struct{ shutdowns atomic.Int32 }

func (c *countingShutdownExporter) ExportSpans(context.Context, []sdktrace.ReadOnlySpan) error {
	return nil
}
func (c *countingShutdownExporter) Shutdown(context.Context) error {
	c.shutdowns.Add(1)
	return nil
}

func TestDeliveryObservingExporter_AbortStopsTheExporterOnce(t *testing.T) {
	inner := &countingShutdownExporter{}
	e := &deliveryObservingExporter{inner: inner, cr: CRKey{"ns", "cr"}}
	e.abort()
	e.abort()
	if got := inner.shutdowns.Load(); got != 1 {
		t.Errorf("inner shutdowns = %d, want 1", got)
	}
	if err := e.ExportSpans(context.Background(), nil); err != errExporterAborted {
		t.Errorf("ExportSpans after abort = %v, want errExporterAborted", err)
	}
}
