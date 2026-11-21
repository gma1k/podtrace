package correlator

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestTheSummaryShowsTheLargestChainsNotTheOldest(t *testing.T) {
	ec := NewErrorCorrelator(time.Minute)
	base := time.Now()
	for n, c := range []struct {
		target string
		size   int
	}{{"old-1", 2}, {"old-2", 2}, {"old-3", 2}, {"old-4", 2}, {"old-5", 2}, {"old-6", 3}, {"big", 25}, {"mid", 12}} {
		for i := range c.size {
			ec.errors = append(ec.errors, &ErrorEvent{ErrorCode: -111, Target: c.target, Timestamp: base.Add(time.Duration(n)*time.Second + time.Duration(i)*time.Millisecond), Context: map[string]string{}})
		}
	}
	ec.seen = len(ec.errors)
	ec.dirty = true
	summary := ec.GetErrorSummary()
	first, second := strings.Index(summary, "on big"), strings.Index(summary, "on mid")
	if first < 0 || second < 0 || first > second {
		t.Fatalf("summary does not lead with the 25- and 12-error chains:\n%s", summary)
	}
	if third := strings.Index(summary, "on old-6"); third < second {
		t.Errorf("the 3-error chain was not ranked third:\n%s", summary)
	}
	if !strings.Contains(summary, "on old-1") || strings.Contains(summary, "on old-3") {
		t.Errorf("equally long chains were not taken earliest first:\n%s", summary)
	}
	if got := strings.Count(summary, "(Severity: "); got != maxChainsShown {
		t.Errorf("showed %d chains, want %d", got, maxChainsShown)
	}
}

func TestLargestChainsKeepsTheEarliestAmongEquals(t *testing.T) {
	var chains []*ErrorChain
	for i := range 3 {
		chains = append(chains, &ErrorChain{RootCause: &ErrorEvent{Target: fmt.Sprint(i)}, Chain: make([]*ErrorEvent, 2)})
	}
	got := largestChains(chains, 10)
	for i, c := range got {
		if c.RootCause.Target != fmt.Sprint(i) {
			t.Errorf("position %d holds chain %s; equally long chains must stay in time order", i, c.RootCause.Target)
		}
	}
	if chains[0].RootCause.Target != "0" || len(largestChains(chains, 1)) != 1 {
		t.Error("largestChains changed its input or ignored n")
	}
}
