package detector

import (
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestDetectIssues_SkipsNilEvents(t *testing.T) {
	evs := []*events.Event{
		nil,
		{Type: events.EventConnect, Error: 1},
		nil,
		{Type: events.EventConnect},
		nil,
	}
	issues := DetectIssues(evs, 10, 100)
	found := false
	for _, s := range issues {
		if s.ID == IDConnectionFailureRate {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a high connection failure rate issue, got %v", issues)
	}
}
