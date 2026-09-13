package tracker

import (
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestAPoolSampleDoesNotMarkItsSpanFailed(t *testing.T) {
	tt := NewTraceTracker()

	tt.ProcessEvent(&events.Event{
		Type:     events.EventDBPoolStats,
		TraceID:  "0af7651916cd43dd8448eb211c80319c",
		SpanID:   "b7ad6b7169203331",
		Error:    95,
		Bytes:    19,
		TCPState: 20,
	}, nil)

	for _, trace := range tt.GetAllTraces() {
		for _, span := range trace.Spans {
			if span.Error {
				t.Errorf("span %q marked failed by a pool sample; 95 is the pool's "+
					"utilization percentage, not a status code", span.SpanID)
			}
		}
	}
}
