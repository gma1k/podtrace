package main

import (
	"context"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
)

// teeEvents fans every event from source out to one primary channel plus
// `auxiliary` additional channels. Go channels deliver each value to exactly
// one receiver, so the report loop, metrics handler, tracing handler, and
// profiling correlator — which all used to receive from the same channel —
// each saw only a random disjoint subset of events, and with --filter events
// randomly bypassed the filter pipeline entirely.
func teeEvents(ctx context.Context, source <-chan *events.Event, auxiliary int) (chan *events.Event, []chan *events.Event) {
	primary := make(chan *events.Event, config.EventChannelBufferSize)
	aux := make([]chan *events.Event, auxiliary)
	for i := range aux {
		aux[i] = make(chan *events.Event, config.EventChannelBufferSize)
	}

	go func() {
		defer close(primary)
		for _, c := range aux {
			defer close(c)
		}
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-source:
				if !ok {
					return
				}
				select {
				case primary <- ev:
				case <-ctx.Done():
					return
				}
				for _, c := range aux {
					select {
					case c <- ev:
					default:
					}
				}
			}
		}
	}()

	return primary, aux
}