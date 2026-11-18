package agent

import (
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestEveryEventTypeHasAReadableSpanName(t *testing.T) {
	seen := map[string]events.EventType{}
	for et := events.EventDNS; et <= events.EventRequestDone; et++ {
		name := eventTypeString(et)
		if strings.HasPrefix(name, "event_") {
			e := &events.Event{Type: et}
			t.Errorf("%s (type %d) is exported as %q", e.TypeString(), et, name)
			continue
		}
		if prev, dup := seen[name]; dup {
			t.Errorf("types %d and %d share the span name %q", prev, et, name)
		}
		seen[name] = et
	}
}
