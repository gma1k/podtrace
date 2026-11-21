package diagnose

import (
	"slices"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestFilterEvents_NotWrappedReturnsMatchesInOrder(t *testing.T) {
	d := NewDiagnostician()
	d.AddEvent(&events.Event{Type: events.EventHTTPReq, Target: "a"})
	d.AddEvent(&events.Event{Type: events.EventConnect, Target: "b"})
	d.AddEvent(&events.Event{Type: events.EventHTTPReq, Target: "c"})

	got := d.FilterEvents(events.EventHTTPReq)
	if len(got) != 2 || got[0].Target != "a" || got[1].Target != "c" {
		t.Fatalf("FilterEvents(HTTPReq) = %+v, want targets [a c]", got)
	}
}

func TestFilterEvents_KeepsArrivalOrderOnceTheBufferSamples(t *testing.T) {
	d := NewDiagnostician()
	d.maxEvents = 4
	d.sampleUniform = falling()
	for _, target := range []string{"a", "b", "c", "d", "e", "f"} {
		d.AddEvent(&events.Event{Type: events.EventDNS, Target: target})
	}
	d.AddEvent(&events.Event{Type: events.EventConnect, Target: "g"})

	got := d.FilterEvents(events.EventDNS)
	var targets []string
	for _, e := range got {
		targets = append(targets, e.Target)
	}
	if !slices.Equal(targets, []string{"c", "d", "e", "f"}) {
		t.Fatalf("FilterEvents(DNS) after sampling = %v, want [c d e f] in arrival order", targets)
	}
}
