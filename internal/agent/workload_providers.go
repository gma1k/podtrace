package agent

import (
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/gma1k/podtrace/internal/events"
)

// workloadProviders gives every observed workload its own TracerProvider so
// that spans arrive under the workload's own service.name.
//
// Why this shape, and not one provider per workload with its own exporter:
//
// service.name is a Resource attribute, and a Resource is bound to a
// TracerProvider — so a single provider cannot describe many workloads. But
// a SpanProcessor can be shared by any number of providers, and the OTLP
// exporter groups spans by Resource when it builds the request. So N
// lightweight providers share ONE processor, ONE queue and ONE exporter.
// The per-node cost is a map entry and a tracer per workload, not N batch
// pipelines.
//
// That sharing is also what keeps the lifecycle single-owner, which is the
// part worth getting right:
//
//   - Providers are created lazily, on the first span for a workload.
//   - Eviction DROPS the map entry and never calls provider.Shutdown().
//     Shutdown would tear down the shared processor and silently stop
//     export for every other workload. A dropped provider owns no
//     goroutine, so it is simply garbage.
//   - Exactly one Shutdown happens, on the base provider, from the
//     exporter's Close.
//   - Reaping runs inline on Export behind a timestamp check rather than in
//     a goroutine, so there is no separate thing to start, stop or leak.
type workloadProviders struct {
	mu    sync.Mutex
	byKey map[string]*workloadProvider

	// base is used for events with no resolvable workload, and owns the
	// shared processor's shutdown.
	base *sdktrace.TracerProvider

	processor sdktrace.SpanProcessor
	sampler   sdktrace.Sampler
	crAttrs   []attribute.KeyValue

	limit      int
	ttl        time.Duration
	lastReaped time.Time
	now        func() time.Time
}

type workloadProvider struct {
	tp       *sdktrace.TracerProvider
	tracer   trace.Tracer
	lastUsed time.Time
}

const (
	// workloadProviderLimit caps distinct providers. Past it, events fall
	// back to the base provider rather than evicting a live workload:
	// losing service.name is recoverable, thrashing the cache is not.
	workloadProviderLimit = 256

	workloadProviderTTL        = 10 * time.Minute
	workloadProviderReapPeriod = time.Minute

	tracerName = "podtrace.io/agent"
)

func newWorkloadProviders(
	base *sdktrace.TracerProvider,
	processor sdktrace.SpanProcessor,
	sampler sdktrace.Sampler,
	crAttrs []attribute.KeyValue,
) *workloadProviders {
	return &workloadProviders{
		byKey:     map[string]*workloadProvider{},
		base:      base,
		processor: processor,
		sampler:   sampler,
		crAttrs:   crAttrs,
		limit:     workloadProviderLimit,
		ttl:       workloadProviderTTL,
		now:       time.Now,
	}
}

// tracerFor returns the tracer whose provider carries this event's workload
// as service.name, falling back to the base tracer when the event has no
// identity or the cache is full.
func (w *workloadProviders) tracerFor(meta *events.K8sMetadata) trace.Tracer {
	if w == nil {
		return nil
	}
	key, ok := workloadProviderKey(meta)
	if !ok {
		return w.base.Tracer(tracerName)
	}

	now := w.now()

	w.mu.Lock()
	defer w.mu.Unlock()

	w.reapLocked(now)

	if existing, hit := w.byKey[key]; hit {
		existing.lastUsed = now
		return existing.tracer
	}
	if len(w.byKey) >= w.limit {
		return w.base.Tracer(tracerName)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(w.processor),
		sdktrace.WithSampler(w.sampler),
		sdktrace.WithResource(w.resourceFor(meta)),
	)
	entry := &workloadProvider{tp: tp, tracer: tp.Tracer(tracerName), lastUsed: now}
	w.byKey[key] = entry
	return entry.tracer
}

// resourceFor builds the workload's Resource.
//
// service.name is the workload, which is what a backend groups by and what
// makes spans land under the application rather than under podtrace.
// podtrace identifies itself as the instrumentation via telemetry.sdk.name,
// which is where the spec puts the producing SDK.
func (w *workloadProviders) resourceFor(meta *events.K8sMetadata) *resource.Resource {
	attrs := make([]attribute.KeyValue, 0, len(w.crAttrs)+8)
	attrs = append(attrs, semconv.ServiceName(meta.WorkloadName))
	attrs = append(attrs, semconv.TelemetrySDKName("podtrace"))
	if meta.Namespace != "" {
		attrs = append(attrs, semconv.ServiceNamespace(meta.Namespace))
	}
	attrs = appendK8sAttributes(attrs, meta)
	attrs = append(attrs, w.crAttrs...)

	// resource.NewSchemaless rather than resource.New: New merges the
	// process-wide default resource, which would stamp the agent's own
	// service.name back over the workload's.
	return resource.NewSchemaless(attrs...)
}

// reapLocked drops providers idle beyond the TTL. Callers hold w.mu.
func (w *workloadProviders) reapLocked(now time.Time) {
	if w.ttl <= 0 || now.Sub(w.lastReaped) < workloadProviderReapPeriod {
		return
	}
	w.lastReaped = now

	cutoff := now.Add(-w.ttl)
	for key, entry := range w.byKey {
		if entry.lastUsed.Before(cutoff) {
			// Deliberately not entry.tp.Shutdown(): the processor is
			// shared, so shutting it down here would stop export for every
			// other workload.
			delete(w.byKey, key)
		}
	}
}

// size reports how many providers are cached. Tests only.
func (w *workloadProviders) size() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.byKey)
}

// workloadProviderKey identifies the workload a span belongs to, and
// reports false when there is not enough identity to name a service.
//
// Keyed on namespace and workload rather than pod: the point is that spans
// group under the application, and a pod-keyed cache would churn an entry
// per rollout for no gain.
func workloadProviderKey(meta *events.K8sMetadata) (string, bool) {
	if meta == nil || meta.Namespace == "" || meta.WorkloadName == "" {
		return "", false
	}
	return meta.Namespace + "/" + meta.WorkloadName, true
}
