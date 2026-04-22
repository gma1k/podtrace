package tracer

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/podtrace/podtrace/internal/events"
)

// Config tunes Engine behaviour. Defaults are applied by NewEngine when a
// zero value is passed. Every field is operationally significant:
//
//   - EventBufferSize controls how much backpressure the backend can absorb
//     before the engine drops events (and increments DroppedEvents).
//   - ExportBatchSize is the soft upper bound on events forwarded to an
//     exporter in a single call; larger values trade latency for throughput.
type Config struct {
	// EventBufferSize sizes the internal channel between the TracerBackend
	// and the dispatch loop. Default 10_000 matches the legacy CLI default.
	EventBufferSize int

	// ExportBatchSize is the target batch size for exporter dispatches.
	// Default 256.
	ExportBatchSize int
}

// EngineStats is a point-in-time counter snapshot. Thread-safe snapshot is
// exposed via Engine.Stats.
type EngineStats struct {
	EventsReceived  int64
	EventsExported  int64
	EventsDropped   int64
	ActiveTargets   int
	ExporterFailure int64
}

// Engine orchestrates a TracerBackend + Exporters over a stream of
// TargetSet snapshots. One instance serves one trace intent end-to-end:
// CLI invocations, agent DaemonSet processes, and session Jobs each
// construct an Engine with mode-appropriate backend/exporters/stream.
type Engine interface {
	// Run blocks until ctx is cancelled or the target stream closes.
	// Returns nil on clean shutdown, otherwise the first terminal error
	// encountered (backend attach failure, backend start failure).
	Run(ctx context.Context, targets <-chan TargetSet) error

	// Stats returns a snapshot of counters. Safe to call concurrently with
	// Run; values may be slightly stale.
	Stats() EngineStats
}

type engine struct {
	backend   TracerBackend
	exporters []Exporter
	cfg       Config

	mu              sync.RWMutex
	activeCgroups   map[string]struct{}
	eventsReceived  int64
	eventsExported  int64
	eventsDropped   int64
	exporterFailure int64
}

// NewEngine composes a backend and a set of exporters into a runnable
// engine. At least one exporter is required; backend must be non-nil.
func NewEngine(backend TracerBackend, exporters []Exporter, cfg Config) (Engine, error) {
	if backend == nil {
		return nil, errors.New("tracer: backend is required")
	}
	if len(exporters) == 0 {
		return nil, errors.New("tracer: at least one exporter is required")
	}
	if cfg.EventBufferSize <= 0 {
		cfg.EventBufferSize = 10_000
	}
	if cfg.ExportBatchSize <= 0 {
		cfg.ExportBatchSize = 256
	}
	return &engine{
		backend:       backend,
		exporters:     exporters,
		cfg:           cfg,
		activeCgroups: make(map[string]struct{}),
	}, nil
}

func (e *engine) Run(ctx context.Context, targets <-chan TargetSet) error {
	if targets == nil {
		return errors.New("tracer: targets channel is required")
	}

	// loop running until the parent ctx is cancelled or the event channel
	// is closed — neither of which is guaranteed by the TracerBackend
	// contract.
	dispatchCtx, cancelDispatch := context.WithCancel(ctx)

	eventCh := make(chan *events.Event, e.cfg.EventBufferSize)
	if err := e.backend.Start(ctx, eventCh); err != nil {
		cancelDispatch()
		return fmt.Errorf("tracer: backend start: %w", err)
	}

	dispatchDone := make(chan struct{})
	go func() {
		defer close(dispatchDone)
		e.dispatchLoop(dispatchCtx, eventCh)
	}()

	shutdown := func() {
		_ = e.backend.Stop()
		cancelDispatch()
		<-dispatchDone
		e.closeExporters()
	}

	for {
		select {
		case <-ctx.Done():
			shutdown()
			return nil
		case set, ok := <-targets:
			if !ok {
				shutdown()
				return nil
			}
			if err := e.applyTargets(set); err != nil {
				// Attach failures are logged-only: missing one cgroup
				// should not tear down the whole engine when other
				// targets are still valid.
				e.mu.Lock()
				e.exporterFailure++
				e.mu.Unlock()
			}
		}
	}
}

func (e *engine) applyTargets(set TargetSet) error {
	desired := make(map[string]Target, len(set))
	for _, t := range set {
		if t.CgroupPath == "" {
			continue
		}
		desired[t.CgroupPath] = t
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Attach any new cgroups. We rely on backend idempotency: re-attaching
	// an existing cgroup is a no-op.
	var firstErr error
	for path, t := range desired {
		if _, ok := e.activeCgroups[path]; ok {
			continue
		}
		if t.ContainerID != "" {
			if err := e.backend.SetContainerID(t.ContainerID); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if err := e.backend.AttachToCgroup(path); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		e.activeCgroups[path] = struct{}{}
	}

	// Detach is the backend's responsibility at Stop(); intra-run detach
	// is not yet part of the TracerBackend contract because the existing
	// internal/ebpf/tracer implementation holds links for lifetime. When
	// a consumer needs dynamic detach, this is the hook point.
	return firstErr
}

func (e *engine) dispatchLoop(ctx context.Context, eventCh <-chan *events.Event) {
	batch := make([]*events.Event, 0, e.cfg.ExportBatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		for _, ex := range e.exporters {
			if err := ex.Export(ctx, batch); err != nil {
				e.mu.Lock()
				e.exporterFailure++
				e.mu.Unlock()
			}
		}
		e.mu.Lock()
		e.eventsExported += int64(len(batch))
		e.mu.Unlock()
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case ev, ok := <-eventCh:
			if !ok {
				flush()
				return
			}
			e.mu.Lock()
			e.eventsReceived++
			e.mu.Unlock()
			batch = append(batch, ev)
			if len(batch) >= e.cfg.ExportBatchSize {
				flush()
			}
		}
	}
}

func (e *engine) closeExporters() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, ex := range e.exporters {
		_ = ex.Close(ctx)
	}
}

func (e *engine) Stats() EngineStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return EngineStats{
		EventsReceived:  e.eventsReceived,
		EventsExported:  e.eventsExported,
		EventsDropped:   e.eventsDropped,
		ActiveTargets:   len(e.activeCgroups),
		ExporterFailure: e.exporterFailure,
	}
}
