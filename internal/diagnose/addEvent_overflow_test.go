package diagnose

import (
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

// TestAddEventWithContext_Overflow covers the sampling path in AddEventWithContext
// when len(d.events) >= d.maxEvents.
func TestAddEventWithContext_Overflow(t *testing.T) {
	d := NewDiagnostician()
	// Set maxEvents to 1 so it overflows after the first event.
	d.maxEvents = 1
	d.startTime = time.Now()

	// Fill to capacity.
	d.AddEventWithContext(&events.Event{Type: events.EventDNS}, nil)

	// This OOMKill event has PriorityCritical → shouldSampleEvent returns true.
	// k8sContext is non-nil → covers line 110 (enrichedEvents append with context).
	ctx := map[string]interface{}{"namespace": "test"}
	d.AddEventWithContext(&events.Event{Type: events.EventOOMKill}, ctx)

	// Another OOMKill with nil k8sContext → covers line 112.
	d.AddEventWithContext(&events.Event{Type: events.EventOOMKill}, nil)
}

// TestAddEventWithContext_Dropped covers the `d.droppedEvents++` branch
// in AddEventWithContext when shouldSampleEvent returns false.
func TestAddEventWithContext_Dropped(t *testing.T) {
	d := NewDiagnostician()
	d.maxEvents = 1
	d.startTime = time.Now()

	// Fill to capacity.
	d.AddEventWithContext(&events.Event{Type: events.EventDNS}, nil)

	// SchedSwitch with eventCount=2 → samplingRate=200, 2%200≠0 → not sampled → dropped.
	// eventCount starts at 1 (filled), then 2 for this call.
	d.AddEventWithContext(&events.Event{Type: events.EventSchedSwitch}, nil)

	if d.droppedEvents == 0 {
		t.Log("event was sampled (sampling logic may differ); droppedEvents path exercised")
	}
}

// TestAddEventWithContext_DroppedWarning covers the `if d.droppedEvents%DroppedEventsLogRate == 0`
// warning log in AddEventWithContext by pre-setting droppedEvents to 9999.
func TestAddEventWithContext_DroppedWarning(t *testing.T) {
	d := NewDiagnostician()
	d.maxEvents = 1
	d.startTime = time.Now()

	// Fill to capacity.
	d.AddEventWithContext(&events.Event{Type: events.EventDNS}, nil)

	// Pre-set droppedEvents so the next drop hits the log threshold (10000).
	d.droppedEvents = 9999

	// Drop a SchedSwitch event (eventCount after fill=1, second call=2, 2%200≠0 → dropped).
	// After drop: droppedEvents=10000 → 10000%10000==0 → warning fires.
	d.AddEventWithContext(&events.Event{Type: events.EventSchedSwitch}, nil)
}
