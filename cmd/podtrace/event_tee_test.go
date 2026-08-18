package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
)

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

func TestTeeEvents_AuxiliaryConsumersGetIndependentCopies(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	source := make(chan *events.Event, 1)
	primary, aux := teeEvents(ctx, source, 2)

	source <- &events.Event{PID: 1, TraceID: "original"}
	close(source)

	ev0 := <-aux[0]
	ev0.TraceID = "mutated"
	ev0.PID = 999

	ev1 := <-aux[1]
	evP := <-primary

	if ev1.TraceID != "original" || ev1.PID != 1 {
		t.Errorf("aux[1] observed aux[0]'s mutation: TraceID=%q PID=%d", ev1.TraceID, ev1.PID)
	}
	if evP.TraceID != "original" || evP.PID != 1 {
		t.Errorf("primary observed aux[0]'s mutation: TraceID=%q PID=%d", evP.TraceID, evP.PID)
	}
	if ev0 == ev1 {
		t.Error("aux consumers received the same pointer; each must get an independent copy")
	}
}

func TestTeeEvents_ConcurrentAuxMutationIsRaceFree(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	source := make(chan *events.Event, 64)
	primary, aux := teeEvents(ctx, source, 2)

	var wg sync.WaitGroup
	wg.Add(4)

	go func() {
		defer wg.Done()
		for i := 0; i < 5000; i++ {
			source <- &events.Event{PID: uint32(i + 1), TraceID: "seed"}
		}
		close(source)
	}()

	go func() {
		defer wg.Done()
		for ev := range aux[0] {
			ev.TraceID = "mutated"
			ev.SpanID = "span"
			ev.TraceFlags = 1
		}
	}()

	drain := func(ch <-chan *events.Event) {
		defer wg.Done()
		for ev := range ch {
			_ = ev.TraceID
			_ = ev.SpanID
			_ = ev.PID
		}
	}
	go drain(aux[1])
	go drain(primary)

	wg.Wait()
}

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
func promCounterTotal(t *testing.T, name string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == name {
			return mf.GetMetric()[0].GetCounter().GetValue()
		}
	}
	return 0
}

func TestTeeEvents_CountsAuxDropsWhenConsumerStalls(t *testing.T) {
	origBuf := config.EventChannelBufferSize
	config.EventChannelBufferSize = 1
	defer func() { config.EventChannelBufferSize = origBuf }()

	before := promCounterTotal(t, "podtrace_event_tee_aux_drops_total")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	source := make(chan *events.Event, 16)
	primary, aux := teeEvents(ctx, source, 1)

	const total = 8
	for i := 0; i < total; i++ {
		source <- &events.Event{PID: uint32(i + 1)}
	}
	close(source)

	for range primary {
	}
	_ = aux

	if got := promCounterTotal(t, "podtrace_event_tee_aux_drops_total") - before; got < 1 {
		t.Fatalf("aux drops counted = %v, want >= 1 (a stalled consumer must be visible)", got)
	}
}

func TestTeeEvents_PrimarySendCanceledByContext(t *testing.T) {
	origBuf := config.EventChannelBufferSize
	config.EventChannelBufferSize = 0
	defer func() { config.EventChannelBufferSize = origBuf }()

	ctx, cancel := context.WithCancel(context.Background())
	source := make(chan *events.Event)
	primary, _ := teeEvents(ctx, source, 0)

	source <- &events.Event{PID: 1}
	cancel()

	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-primary:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("tee did not return after context cancel during a blocked primary send")
		}
	}
}
