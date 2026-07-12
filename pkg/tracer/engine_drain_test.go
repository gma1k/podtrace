package tracer_test

import (
	"context"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/pkg/tracer"
)

type stopEmittingBackend struct {
	*mockBackend
}

func (b *stopEmittingBackend) Stop() error {
	b.mu.Lock()
	ch := b.eventCh
	b.mu.Unlock()
	if ch != nil {
		ch <- &events.Event{Type: events.EventDNS}
	}
	return b.mockBackend.Stop()
}

func TestEngine_DrainsEventsEmittedDuringStop(t *testing.T) {
	backend := &stopEmittingBackend{mockBackend: &mockBackend{}}
	exp := &recordingExporter{name: "rec"}
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{exp}, tracer.Config{EventBufferSize: 16, ExportBatchSize: 256})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	targets := make(chan tracer.TargetSet, 1)
	targets <- tracer.TargetSet{{CgroupPath: "/c"}}
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, targets) }()

	waitUntil(t, 2*time.Second, func() bool { return len(backend.activePaths()) == 1 })

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := exp.totalEvents(); got != 1 {
		t.Fatalf("event emitted during Stop() was lost: exporter saw %d events, want 1", got)
	}
	if s := eng.Stats(); s.EventsExported != 1 {
		t.Fatalf("EventsExported=%d, want 1 (final event must be flushed)", s.EventsExported)
	}
}
