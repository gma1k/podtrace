package detector

import (
	"strings"
	"testing"

	"github.com/podtrace/podtrace/internal/events"
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
		if strings.Contains(s, "High connection failure rate") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a high connection failure rate issue, got %v", issues)
	}
}
