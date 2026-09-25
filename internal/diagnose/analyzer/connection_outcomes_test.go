package analyzer

import (
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestConnectionOutcomesScoreEachAttemptOnce(t *testing.T) {
	connects := []*events.Event{
		{Type: events.EventConnect},
		{Type: events.EventConnect},
		{Type: events.EventConnect, Error: -113},
		{Type: events.EventConnect, Error: -101},
		{Type: events.EventConnect, Error: -97},
		nil,
	}
	results := []*events.Event{
		{Type: events.EventConnectResult},
		{Type: events.EventConnectResult, Error: -111},
		nil,
	}

	attempts, failed, unreachable, breakdown := ConnectionOutcomes(connects, results)
	if attempts != 3 || failed != 2 {
		t.Errorf("attempts=%d failed=%d, want 3 and 2: two connects queued a SYN and were "+
			"scored by their handshake results, one failed inside connect()", attempts, failed)
	}
	if unreachable != 2 {
		t.Errorf("unreachable = %d, want 2: ENETUNREACH and EAFNOSUPPORT mean no route for "+
			"the address family, which a dual-stack client falls back from", unreachable)
	}
	if breakdown[-111] != 1 || breakdown[-113] != 1 || len(breakdown) != 2 {
		t.Errorf("breakdown = %v, want one ECONNREFUSED and one EHOSTUNREACH", breakdown)
	}
}

func TestFailurePercentIsZeroWithoutAttempts(t *testing.T) {
	if got := FailurePercent(0, 0); got != 0 {
		t.Errorf("FailurePercent(0, 0) = %v, want 0", got)
	}
	if got := FailurePercent(1, 4); got != 25 {
		t.Errorf("FailurePercent(1, 4) = %v, want 25", got)
	}
}
