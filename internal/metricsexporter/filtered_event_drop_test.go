package metricsexporter

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRecordFilteredEventDrop_IncrementsCounter(t *testing.T) {
	before := testutil.ToFloat64(filteredEventDropsCounter)
	RecordFilteredEventDrop()
	RecordFilteredEventDrop()
	after := testutil.ToFloat64(filteredEventDropsCounter)
	if after-before != 2 {
		t.Errorf("filteredEventDropsCounter delta = %v, want 2", after-before)
	}
}

func TestRecordFilteredEventDrop_DoesNotTouchRingBufferCounter(t *testing.T) {
	before := testutil.ToFloat64(ringBufferDropsCounter)
	RecordFilteredEventDrop()
	after := testutil.ToFloat64(ringBufferDropsCounter)
	if after != before {
		t.Errorf("ring-buffer drop counter changed by %v, want 0 (distinct failure mode)", after-before)
	}
}
