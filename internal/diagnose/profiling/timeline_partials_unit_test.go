package profiling

import (
	"testing"

	"github.com/podtrace/podtrace/internal/events"
)

func TestMinEventTimestamp_Branches(t *testing.T) {
	tests := []struct {
		name string
		ts   []uint64
		want uint64
	}{
		{
			name: "single event",
			ts:   []uint64{42},
			want: 42,
		},
		{
			name: "ascending (origin stays first)",
			ts:   []uint64{10, 20, 30},
			want: 10,
		},
		{
			name: "later event smaller updates origin",
			ts:   []uint64{30, 20, 10},
			want: 10,
		},
		{
			name: "minimum in the middle",
			ts:   []uint64{30, 5, 40, 25},
			want: 5,
		},
		{
			name: "includes zero timestamp",
			ts:   []uint64{100, 0, 50},
			want: 0,
		},
		{
			name: "all equal",
			ts:   []uint64{7, 7, 7},
			want: 7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evs := make([]*events.Event, len(tt.ts))
			for i, ts := range tt.ts {
				evs[i] = &events.Event{Timestamp: ts}
			}
			if got := minEventTimestamp(evs); got != tt.want {
				t.Fatalf("minEventTimestamp = %d, want %d", got, tt.want)
			}
		})
	}
}
