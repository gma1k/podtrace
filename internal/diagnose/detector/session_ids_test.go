package detector

import (
	"slices"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestSessionIDsAreExactlyTheIssuesASessionRaises(t *testing.T) {
	batch := []*events.Event{
		{Type: events.EventResourceLimit, TCPState: 0, Error: 95, Bytes: 950000000},
	}
	for i := 0; i < 10; i++ {
		batch = append(batch, &events.Event{Type: events.EventConnect, Error: 111})
	}
	for i := 0; i < 100; i++ {
		batch = append(batch, &events.Event{Type: events.EventTCPSend, LatencyNS: 150000000})
	}

	raised := map[ID]bool{}
	for _, issue := range DetectIssues(batch, 10.0, 100.0) {
		raised[issue.ID] = true
		if !slices.Contains(SessionIDs, issue.ID) {
			t.Errorf("DetectIssues raised %s, which SessionIDs does not list", issue.ID)
		}
	}
	for _, id := range SessionIDs {
		if !raised[id] {
			t.Errorf("SessionIDs lists %s, but a batch built to trip every rule did not raise it", id)
		}
		if !slices.Contains(Registry, id) {
			t.Errorf("SessionIDs lists %s, which is not in the registry", id)
		}
	}
}
