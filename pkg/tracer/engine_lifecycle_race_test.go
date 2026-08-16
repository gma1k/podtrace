package tracer_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/pkg/tracer"
)

func (m *mockBackend) trySend(ev *events.Event, stop <-chan struct{}) bool {
	m.mu.Lock()
	ch := m.eventCh
	m.mu.Unlock()
	if ch == nil {
		return false
	}
	select {
	case ch <- ev:
		return true
	case <-stop:
		return false
	}
}

func TestEngine_LifecycleConcurrentWithEventPath(t *testing.T) {
	backend := &mockBackend{}
	exp := &recordingExporter{name: "rec"}
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{exp}, tracer.Config{
		EventBufferSize:     256,
		ExportBatchSize:     8,
		ExportFlushInterval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targets := make(chan tracer.TargetSet, 64)
	targets <- tracer.TargetSet{{CgroupPath: "/c/seed"}}

	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, targets) }()

	waitUntil(t, 2*time.Second, func() bool { return len(backend.attachedPaths()) == 1 })

	stop := make(chan struct{})
	var wg sync.WaitGroup

	for e := 0; e < 4; e++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if !backend.trySend(&events.Event{Type: events.EventDNS}, stop) {
					return
				}
			}
		}()
	}

	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = eng.Stats()
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			select {
			case targets <- tracer.TargetSet{{CgroupPath: fmtPath(i%3, i)}, {CgroupPath: fmtPath(i%3, i-1)}}:
				i++
			case <-stop:
				return
			}
		}
	}()

	waitUntil(t, 3*time.Second, func() bool { return eng.Stats().EventsReceived > 100 })

	close(stop)
	wg.Wait()

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}

	if s := eng.Stats(); s.EventsReceived == 0 {
		t.Fatalf("expected events received, stats=%+v", s)
	}
}
