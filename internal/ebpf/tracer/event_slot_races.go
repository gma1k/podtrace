package tracer

import (
	"encoding/binary"
	"fmt"

	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/logger"
)

const (
	eventSlotMapName    = "event_buf"
	eventSlotRaceReason = "event_slot_race"
	eventSlotCount      = 3
)

type eventSlotMap interface {
	LookupBytes(key interface{}) ([]byte, error)
	ValueSize() uint32
}

// readEventSlotRaces sums, over every CPU and scratch slot, the records the
// kernel discarded because another task reused the slot while the program
// filling it was preempted. The counter is the last field of struct
// event_slot.
func readEventSlotRaces(m eventSlotMap) (uint64, error) {
	size := int(m.ValueSize())
	if size < 8 {
		return 0, fmt.Errorf("event slot value of %d bytes has no race counter", size)
	}
	stride := (size + 7) &^ 7
	var total uint64
	for slot := uint32(0); slot < eventSlotCount; slot++ {
		buf, err := m.LookupBytes(slot)
		if err != nil {
			return 0, err
		}
		for off := 0; off+stride <= len(buf); off += stride {
			total += binary.NativeEndian.Uint64(buf[off+size-8 : off+size])
		}
	}
	return total, nil
}

// pollEventSlotRaces reports the discards since the previous poll as kernel
// event loss, so they show up next to ring buffer overruns.
func (t *Tracer) pollEventSlotRaces() {
	if t.collection == nil {
		return
	}
	m := t.collection.Maps[eventSlotMapName]
	if m == nil {
		return
	}
	t.recordEventSlotRaces(m)
}

func (t *Tracer) recordEventSlotRaces(m eventSlotMap) {
	total, err := readEventSlotRaces(m)
	if err != nil {
		logger.Debug("Reading the event slot race counter failed", zap.Error(err))
		return
	}
	previous := t.eventSlotRaces.Swap(total)
	if total <= previous {
		return
	}
	delta := total - previous
	t.reportDrop(eventSlotRaceReason, int(min(delta, uint64(1<<31-1))))
	logger.Debug("Kernel discarded events whose scratch slot was reused by a preempting task",
		zap.Uint64("count", delta))
}
