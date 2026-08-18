package main

import (
	"context"

	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/logger"
	"github.com/gma1k/podtrace/internal/metricsexporter"
)

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
		var auxDrops uint64
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
				for i, c := range aux {
					evCopy := *ev
					select {
					case c <- &evCopy:
					default:
						auxDrops++
						metricsexporter.RecordTeeAuxDrop()
						if auxDrops == 1 || auxDrops%uint64(config.DroppedEventsLogRate) == 0 {
							logger.Warn("Auxiliary event channel full; dropping event for a secondary consumer (metrics/tracing/profiling will undercount)",
								zap.Int("aux_index", i),
								zap.Uint64("total_aux_drops", auxDrops),
								zap.String("event_type", ev.TypeString()))
						}
					}
				}
			}
		}
	}()

	return primary, aux
}
