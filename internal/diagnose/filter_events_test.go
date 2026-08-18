package diagnose

import (
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

func TestFilterEvents_WalksRingInOrderAcrossWrap(t *testing.T) {
	a := &events.Event{Type: events.EventDNS, Target: "a"}
	b := &events.Event{Type: events.EventConnect, Target: "b"}
	c := &events.Event{Type: events.EventDNS, Target: "c"}
	dd := &events.Event{Type: events.EventConnect, Target: "d"}

	d := NewDiagnostician()
	d.maxEvents = 4
	d.events = []*events.Event{c, dd, a, b}
	d.evHead = 2
	d.wrapped = true

	got := d.FilterEvents(events.EventDNS)
	if len(got) != 2 || got[0].Target != "a" || got[1].Target != "c" {
		t.Fatalf("FilterEvents(DNS) across wrap = %+v, want targets [a c] in ring order", got)
	}
}
