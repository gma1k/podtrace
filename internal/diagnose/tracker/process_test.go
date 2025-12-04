package tracker

import (
	"testing"

	"github.com/podtrace/podtrace/internal/events"
)

func TestAnalyzeProcessActivity_UsesProcessNameFromEvents(t *testing.T) {
	evs := []*events.Event{
		{PID: 1234, ProcessName: "proc-a"},
		{PID: 1234, ProcessName: "proc-a"},
		{PID: 5678, ProcessName: "proc-b"},
	}

	pids := AnalyzeProcessActivity(evs)
	if len(pids) != 2 {
		t.Fatalf("expected 2 pid entries, got %d", len(pids))
	}
	if pids[0].Name == "" || pids[1].Name == "" {
		t.Fatalf("expected names to be populated from events")
	}
}
