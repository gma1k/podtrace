package diagnose

import (
	"testing"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
)

func TestAMeasurementInErrorIsNotPrioritisedAsAFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		ev   *events.Event
	}{
		{"pool utilization", &events.Event{Type: events.EventDBPoolStats, Error: 95}},
		{"resource utilization", &events.Event{Type: events.EventResourceLimit, Error: 95}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := getEventPriority(tc.ev); got == config.PriorityCritical {
				t.Errorf("priority = critical; the field holds a percentage, not an error "+
					"code, so a busy workload would evict real failures from a full sample "+
					"buffer (Error=%d)", tc.ev.Error)
			}
		})
	}
}

func TestARealErrorCodeIsStillCritical(t *testing.T) {
	if got := getEventPriority(&events.Event{Type: events.EventTCPRecv, Error: -11}); got != config.PriorityCritical {
		t.Errorf("priority = %d, want critical for a negative errno", got)
	}
}
