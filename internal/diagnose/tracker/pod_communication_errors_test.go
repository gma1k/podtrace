package tracker

import (
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestPodToPodErrorsCountOnlyRealFailures(t *testing.T) {
	tr := NewPodCommunicationTracker("source-pod", "default")
	ctx := map[string]interface{}{"target_pod": "db-0", "target_namespace": "default"}
	for _, e := range []*events.Event{
		{Type: events.EventTCPRecv, Error: -11},
		{Type: events.EventUDPRecv, Error: -11},
		{Type: events.EventTCPSend, Error: -512},
		{Type: events.EventConnect, Error: -512},
		{Type: events.EventTCPSend, Error: 0},
		{Type: events.EventTCPRecv, Error: -104},
		{Type: events.EventUDPSend, Error: -111},
		{Type: events.EventConnect, Error: -111},
	} {
		tr.ProcessEvent(e, ctx)
	}
	summaries := tr.GetSummary()
	if len(summaries) != 1 {
		t.Fatalf("summaries = %v, want one", summaries)
	}
	if summaries[0].ErrorCount != 3 {
		t.Errorf("ErrorCount = %d, want 3 (ECONNRESET, a UDP ECONNREFUSED, a refused connect)", summaries[0].ErrorCount)
	}
}
