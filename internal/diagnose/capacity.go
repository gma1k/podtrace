package diagnose

import (
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/memlimit"
)

// What the event buffer may hold of the container's memory, and what one
// buffered event costs on the heap with its strings and its slots in the
// event and context buffers, its enrichment being shared.
const (
	bufferShareOfMemory  = 0.25
	bufferedEventBytes   = 512
	minimumEventCapacity = 10_000
)

// containerMemoryLimit is memlimit.ContainerLimit, replaceable in tests.
var containerMemoryLimit = memlimit.ContainerLimit

// defaultEventCapacity is how many events a diagnostician keeps before it
// starts sampling: config.MaxEvents, or fewer when the container's memory
// limit could not hold that many.
func defaultEventCapacity() int {
	limit, ok := containerMemoryLimit()
	if !ok {
		return config.MaxEvents
	}
	return eventCapacityFor(limit)
}

func eventCapacityFor(limit int64) int {
	n := int64(float64(limit)*bufferShareOfMemory) / bufferedEventBytes
	switch {
	case n < minimumEventCapacity:
		return minimumEventCapacity
	case n > config.MaxEvents:
		return config.MaxEvents
	}
	return int(n)
}

// EventCapacity is how many events the diagnostician buffers before it
// samples.
func (d *Diagnostician) EventCapacity() int {
	return d.maxEvents
}
