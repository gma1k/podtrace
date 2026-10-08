package correlator

import (
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

func TestADNSChainNamesItsAnswerAndHowToFixIt(t *testing.T) {
	ec := NewErrorCorrelator(30 * time.Second)
	base := uint64(time.Now().UnixNano())
	for i := 0; i < 3; i++ {
		ec.AddEvent(&events.Event{
			Type: events.EventDNS, Target: "example.com", Error: events.DNSErrorTimeout,
			Timestamp: base + uint64(i)*uint64(time.Second),
		}, nil)
	}
	summary := ec.GetErrorSummary()
	if !strings.Contains(summary, "(answer: timeout)") {
		t.Errorf("the chain does not name the answer:\n%s", summary)
	}
	if !strings.Contains(summary, "reachable on port 53") || strings.Contains(summary, "firewall rules") {
		t.Errorf("a DNS timeout got the errno suggestion, not the resolver one:\n%s", summary)
	}
}

func TestEveryFailedDNSAnswerHasASuggestion(t *testing.T) {
	for _, answer := range []string{events.DNSAnswerTimeout, events.DNSAnswerServFail, events.DNSAnswerRefused, events.DNSAnswerOther} {
		if dnsSuggestions[answer] == "" {
			t.Errorf("%s has no suggestion", answer)
		}
	}
}

func TestANonDNSErrorKeepsItsCode(t *testing.T) {
	if got := errorCodeText(&ErrorEvent{ErrorCode: -111, Event: &events.Event{Type: events.EventConnect}}); got != "code: -111" {
		t.Errorf("got %q", got)
	}
}
