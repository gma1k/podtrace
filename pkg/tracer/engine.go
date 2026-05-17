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
type Config struct {
	EventBufferSize int

	ExportBatchSize int

	Observer EngineObserver
}

// EngineStats is a point-in-time counter snapshot. Thread-safe snapshot is
// exposed via Engine.Stats.
type EngineStats struct {
	EventsReceived   int64
	EventsExported   int64
	EventsDropped    int64
	ActiveTargets    int
	ExporterFailure  int64
	CgroupsAttached  int64
	CgroupsDetached  int64
}

// Engine orchestrates a TracerBackend + Exporters over a stream of
// TargetSet snapshots. One instance serves one trace intent end-to-end:
// CLI invocations, agent DaemonSet processes, and session Jobs each
// construct an Engine with mode-appropriate backend/exporters/stream.
type Engine interface {
	Run(ctx context.Context, targets <-chan TargetSet) error

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
	cgroupsAttached int64
	cgroupsDetached int64
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
				e.mu.Lock()
				e.exporterFailure++
				e.mu.Unlock()
			}
		}
	}
}

// applyTargets reconciles the engine's view of attached cgroups with the
// requested TargetSet via a single backend snapshot replace.
func (e *engine) applyTargets(set TargetSet) error {
	desired := make(map[string]Target, len(set))
	snapshot := make([]CgroupTarget, 0, len(set))
	for _, t := range set {
		if t.CgroupPath == "" {
			continue
		}
		if _, dup := desired[t.CgroupPath]; dup {
			continue
		}
		desired[t.CgroupPath] = t
		snapshot = append(snapshot, CgroupTarget{
			CgroupPath:  t.CgroupPath,
			ContainerID: t.ContainerID,
		})
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	added, removed := 0, 0
	for path := range desired {
		if _, ok := e.activeCgroups[path]; !ok {
			added++
		}
	}
	for path := range e.activeCgroups {
		if _, ok := desired[path]; !ok {
			removed++
		}
	}

	if added == 0 && removed == 0 {
		return nil
	}

	if err := e.backend.SetCgroups(snapshot); err != nil {
		return err
	}

	for path, t := range desired {
		if t.ContainerID == "" {
			continue
		}
		if _, alreadyActive := e.activeCgroups[path]; alreadyActive {
			continue
		}
		if err := e.backend.SetContainerID(t.ContainerID); err != nil {
			e.exporterFailure++
		}
	}

	next := make(map[string]struct{}, len(desired))
	for path := range desired {
		next[path] = struct{}{}
	}
	e.activeCgroups = next
	e.cgroupsAttached += int64(added)
	e.cgroupsDetached += int64(removed)

	if obs := e.cfg.Observer; obs != nil {
		if added > 0 {
			obs.OnCgroupsAttached(added)
		}
		if removed > 0 {
			obs.OnCgroupsDetached(removed)
		}
	}
	return nil
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
		CgroupsAttached: e.cgroupsAttached,
		CgroupsDetached: e.cgroupsDetached,
	}
}
