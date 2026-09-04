package agent

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/gma1k/podtrace/internal/events"
)

type countingProcessor struct {
	sdktrace.SpanProcessor
	shutdowns atomic.Int32
	ended     atomic.Int32
}

func (c *countingProcessor) OnStart(context.Context, sdktrace.ReadWriteSpan) {}
func (c *countingProcessor) OnEnd(sdktrace.ReadOnlySpan)                     { c.ended.Add(1) }
func (c *countingProcessor) ForceFlush(context.Context) error                { return nil }
func (c *countingProcessor) Shutdown(context.Context) error {
	c.shutdowns.Add(1)
	return nil
}

func newTestProviders(t *testing.T, proc sdktrace.SpanProcessor, clock func() time.Time) *workloadProviders {
	t.Helper()
	base := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(proc))
	w := newWorkloadProviders(base, proc, sdktrace.AlwaysSample(),
		[]attribute.KeyValue{attribute.String("podtrace.cr.name", "cr")})
	if clock != nil {
		w.now = clock
	}
	return w
}

func meta(namespace, workload string) *events.K8sMetadata {
	return &events.K8sMetadata{
		Namespace:     namespace,
		WorkloadName:  workload,
		WorkloadKind:  "Deployment",
		ContainerName: "app",
		PodName:       workload + "-abc123",
	}
}

func TestEachWorkloadGetsItsOwnProvider(t *testing.T) {
	proc := &countingProcessor{}
	w := newTestProviders(t, proc, nil)

	a := w.tracerFor(meta("shop", "checkout"))
	b := w.tracerFor(meta("shop", "cart"))
	again := w.tracerFor(meta("shop", "checkout"))

	if a == b {
		t.Error("two workloads share a tracer, so they would share service.name")
	}
	if a != again {
		t.Error("the same workload got a second provider; the cache is not hitting")
	}
	if got := w.size(); got != 2 {
		t.Errorf("cached %d providers, want 2", got)
	}
}

func TestSpansCarryTheWorkloadAsServiceName(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	w := newTestProviders(t, rec, nil)

	tr := w.tracerFor(meta("shop", "checkout"))
	_, span := tr.Start(context.Background(), "event")
	span.End()

	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("recorded %d spans, want 1", len(spans))
	}

	attrs := map[string]string{}
	for _, kv := range spans[0].Resource().Attributes() {
		attrs[string(kv.Key)] = kv.Value.String()
	}

	if attrs["service.name"] != "checkout" {
		t.Errorf("service.name = %q, want checkout. Collapsing every workload under "+
			"one service is what made Jaeger's service list useless", attrs["service.name"])
	}
	if attrs["telemetry.sdk.name"] != "podtrace" {
		t.Errorf("telemetry.sdk.name = %q, want podtrace; that is where the producing "+
			"instrumentation belongs", attrs["telemetry.sdk.name"])
	}
	if attrs["service.namespace"] != "shop" {
		t.Errorf("service.namespace = %q, want shop", attrs["service.namespace"])
	}
	if attrs["podtrace.cr.name"] != "cr" {
		t.Errorf("CR attribution lost: podtrace.cr.name = %q", attrs["podtrace.cr.name"])
	}
	if attrs["k8s.deployment.name"] != "checkout" {
		t.Errorf("k8s.deployment.name = %q, want checkout", attrs["k8s.deployment.name"])
	}
}

func TestEventsWithNoIdentityFallBackToTheBaseProvider(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	w := newTestProviders(t, rec, nil)

	for _, m := range []*events.K8sMetadata{
		nil,
		{},
		{Namespace: "shop"},
		{WorkloadName: "checkout"},
	} {
		if tr := w.tracerFor(m); tr == nil {
			t.Fatal("tracerFor returned nil; Export would panic")
		}
	}
	if got := w.size(); got != 0 {
		t.Errorf("cached %d providers for unidentifiable events, want 0", got)
	}
}

func TestEvictionNeverShutsDownTheSharedProcessor(t *testing.T) {
	proc := &countingProcessor{}
	clock := time.Now()
	w := newTestProviders(t, proc, func() time.Time { return clock })

	w.tracerFor(meta("shop", "gone"))
	if got := w.size(); got != 1 {
		t.Fatalf("size = %d, want 1", got)
	}

	clock = clock.Add(workloadProviderTTL + workloadProviderReapPeriod + time.Minute)
	w.tracerFor(meta("shop", "still-here"))

	if got := w.size(); got != 1 {
		t.Errorf("size = %d after eviction, want 1 (the idle one gone, the live one kept)", got)
	}
	if got := proc.shutdowns.Load(); got != 0 {
		t.Errorf("processor was shut down %d times during eviction. The processor is "+
			"shared, so shutting it down here silently stops export for every other "+
			"workload — eviction must only drop the map entry", got)
	}

	// Export must still work for the surviving workload.
	tr := w.tracerFor(meta("shop", "still-here"))
	_, span := tr.Start(context.Background(), "after-eviction")
	span.End()
	if got := proc.ended.Load(); got != 1 {
		t.Errorf("processor saw %d ended spans after an eviction, want 1", got)
	}
}

func TestLiveWorkloadsSurviveReaping(t *testing.T) {
	proc := &countingProcessor{}
	clock := time.Now()
	w := newTestProviders(t, proc, func() time.Time { return clock })

	for i := 0; i < 4; i++ {
		w.tracerFor(meta("shop", "busy"))
		clock = clock.Add(workloadProviderReapPeriod + time.Second)
	}

	if got := w.size(); got != 1 {
		t.Errorf("size = %d; a workload touched every reap period must never be "+
			"evicted", got)
	}
}

func TestCacheFallsBackRatherThanThrashingAtTheLimit(t *testing.T) {
	proc := &countingProcessor{}
	w := newTestProviders(t, proc, nil)
	w.limit = 3

	for i := 0; i < 20; i++ {
		if tr := w.tracerFor(meta("shop", fmt.Sprintf("w%d", i))); tr == nil {
			t.Fatal("tracerFor returned nil at the limit")
		}
	}

	if got := w.size(); got != 3 {
		t.Errorf("size = %d, want 3; past the cap events must fall back to the base "+
			"provider rather than evicting a live workload", got)
	}
}

func TestReapingIsRateLimited(t *testing.T) {
	proc := &countingProcessor{}
	clock := time.Now()
	w := newTestProviders(t, proc, func() time.Time { return clock })

	w.tracerFor(meta("shop", "a"))
	clock = clock.Add(workloadProviderTTL + time.Minute)

	// Within the reap period of the first sweep, so the idle entry stays.
	w.lastReaped = clock
	w.tracerFor(meta("shop", "b"))
	if got := w.size(); got != 2 {
		t.Errorf("size = %d; reaping must not run on every call, or a hot path pays "+
			"a full map scan per event", got)
	}
}

func TestZeroTTLDisablesReaping(t *testing.T) {
	proc := &countingProcessor{}
	clock := time.Now()
	w := newTestProviders(t, proc, func() time.Time { return clock })
	w.ttl = 0

	w.tracerFor(meta("shop", "a"))
	clock = clock.Add(24 * time.Hour)
	w.tracerFor(meta("shop", "b"))

	if got := w.size(); got != 2 {
		t.Errorf("size = %d, want 2; a zero TTL must never evict", got)
	}
}

func TestConcurrentTracerForIsSafe(t *testing.T) {
	proc := &countingProcessor{}
	w := newTestProviders(t, proc, nil)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				tr := w.tracerFor(meta("shop", fmt.Sprintf("w%d", (n+j)%8)))
				_, span := tr.Start(context.Background(), "concurrent")
				span.End()
			}
		}(i)
	}
	wg.Wait()

	if got := w.size(); got != 8 {
		t.Errorf("size = %d, want 8; concurrent creation duplicated providers", got)
	}
}

func TestNilProvidersCacheIsInert(t *testing.T) {
	var w *workloadProviders
	if tr := w.tracerFor(meta("shop", "checkout")); tr != nil {
		t.Error("a nil cache must return a nil tracer rather than panicking")
	}
}

func TestWorkloadProviderKeyIgnoresPod(t *testing.T) {
	a, okA := workloadProviderKey(&events.K8sMetadata{
		Namespace: "shop", WorkloadName: "checkout", PodName: "checkout-aaa",
	})
	b, okB := workloadProviderKey(&events.K8sMetadata{
		Namespace: "shop", WorkloadName: "checkout", PodName: "checkout-bbb",
	})

	if !okA || !okB {
		t.Fatal("both should be identifiable")
	}
	if a != b {
		t.Errorf("keys differ across pods (%q vs %q); a pod-keyed cache churns an "+
			"entry per rollout for no gain", a, b)
	}
}

func TestSharedProcessorIsShutDownExactlyOnce(t *testing.T) {
	proc := &countingProcessor{}
	base := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(proc))
	w := newWorkloadProviders(base, proc, sdktrace.AlwaysSample(), nil)

	for i := 0; i < 5; i++ {
		w.tracerFor(meta("shop", fmt.Sprintf("w%d", i)))
	}
	if got := w.size(); got != 5 {
		t.Fatalf("size = %d, want 5", got)
	}

	// What the exporter's Close does: shut down the base provider only.
	if err := base.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	if got := proc.shutdowns.Load(); got != 1 {
		t.Errorf("processor shut down %d times, want exactly 1. Five providers share "+
			"it, so shutting each one down would call Shutdown five times and the "+
			"exporter's own accounting would be wrong", got)
	}
}
