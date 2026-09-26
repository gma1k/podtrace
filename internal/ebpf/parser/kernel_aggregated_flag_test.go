package parser

import (
	"encoding/binary"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func v9Record(aggRecorded byte) []byte {
	const bpfEventSize = 432
	const aggRecordedOffset = 425
	data := make([]byte, bpfEventSize)
	binary.LittleEndian.PutUint32(data[12:], uint32(events.EventSchedSwitch))
	data[aggRecordedOffset] = aggRecorded
	return data
}

func TestTheKernelAggregationFlagIsDecoded(t *testing.T) {
	event := ParseEvent(v9Record(1))
	if event == nil {
		t.Fatal("ParseEvent returned nil")
	}
	if !event.KernelAggregated {
		t.Error("agg_recorded=1 at offset 425 did not decode as KernelAggregated.\n\n" +
			"The metrics plane counts an event itself exactly when this is false, so a " +
			"missed flag double-counts every kernel-aggregated observation.")
	}
	PutEvent(event)
}

func TestAPooledEventDoesNotKeepTheFlag(t *testing.T) {
	PutEvent(ParseEvent(v9Record(1)))
	event := ParseEvent(v9Record(0))
	if event.KernelAggregated {
		t.Error("an event reused from the pool kept KernelAggregated from its previous " +
			"life, so a probe that never aggregates would be skipped by the metrics plane")
	}
}
