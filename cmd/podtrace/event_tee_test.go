package main

import (
	"context"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

// TestTeeEvents_EveryConsumerSeesEveryEvent is a regression test: the
// report loop, metrics handler, and tracing handler all used to receive from
// the SAME channel, so each saw only a random disjoint subset of events.
func TestTeeEvents_EveryConsumerSeesEveryEvent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	source := make(chan *events.Event, 16)
	primary, aux := teeEvents(ctx, source, 2)
	if len(aux) != 2 {
		t.Fatalf("aux channels = %d, want 2", len(aux))
	}

	const total = 10
	for i := 0; i < total; i++ {
		source <- &events.Event{PID: uint32(i + 1)}
	}
	close(source)

	count := func(name string, ch <-chan *events.Event) {
		t.Helper()
		got := 0
		deadline := time.After(5 * time.Second)
		for {
			select {
			case _, ok := <-ch:
				if !ok {
					if got != total {
						t.Errorf("%s received %d events, want %d", name, got, total)
					}
					return
				}
				got++
			case <-deadline:
				t.Fatalf("%s timed out after %d events", name, got)
			}
		}
	}

	count("primary", primary)
	count("aux[0]", aux[0])
	count("aux[1]", aux[1])
}

// TestTeeEvents_SlowAuxiliaryDoesNotStallPrimary: auxiliary sends are
// non-blocking, so a consumer that never drains its channel must not stop
// the report pipeline.
func TestTeeEvents_SlowAuxiliaryDoesNotStallPrimary(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	source := make(chan *events.Event)
	primary, _ := teeEvents(ctx, source, 1) // aux never read

	const total = 20000
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < total; i++ {
			source <- &events.Event{PID: uint32(i + 1)}
		}
		close(source)
	}()

	got := 0
	deadline := time.After(10 * time.Second)
	for {
		select {
		case _, ok := <-primary:
			if !ok {
				if got != total {
					t.Fatalf("primary received %d events, want %d", got, total)
				}
				<-done
				return
			}
			got++
		case <-deadline:
			t.Fatalf("primary stalled after %d events (auxiliary backpressure leaked)", got)
		}
	}
}