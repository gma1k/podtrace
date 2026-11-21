package diagnose

import (
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestTheSeenCountsIncludeWhatTheBufferSampledOut(t *testing.T) {
	d := NewDiagnostician()
	d.maxEvents = 10
	d.sampleUniform = rising()
	for i := range 30 {
		ev := &events.Event{Type: events.EventConnect}
		if i%3 == 0 {
			ev.Error = -111
		}
		d.AddEvent(ev)
	}
	d.AddEvent(&events.Event{Type: events.EventDNS})
	if kept := len(d.GetEvents()); kept >= 31 {
		t.Fatalf("kept %d of 31; the buffer never sampled", kept)
	}
	byType := d.EventsSeenByType()
	if byType[events.EventConnect] != 30 || byType[events.EventDNS] != 1 || d.ErrorsSeen() != 10 {
		t.Errorf("seen %v with %d errors, want 30 connects, 1 DNS lookup and 10 errors", byType, d.ErrorsSeen())
	}
	byType[events.EventConnect] = 0
	if d.EventsSeenByType()[events.EventConnect] != 30 {
		t.Error("EventsSeenByType handed out its own map")
	}
}

func TestADiagnosticianThatSawNothingHasNoSeenCounts(t *testing.T) {
	d := NewDiagnostician()
	if len(d.EventsSeenByType()) != 0 || d.ErrorsSeen() != 0 {
		t.Error("a new diagnostician reported events")
	}
}
