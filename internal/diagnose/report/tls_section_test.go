package report

import (
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

func TestTheTLSSectionCountsHandshakesFailuresAndWhoFailed(t *testing.T) {
	d := &mockDiagnostician{
		events: []*events.Event{
			{Type: events.EventTLSHandshake, LatencyNS: 4_000_000, PID: 7, ProcessName: "curl"},
			{Type: events.EventTLSHandshake, LatencyNS: 2_000_000, PID: 7, ProcessName: "curl", Error: -1},
			{Type: events.EventTLSHandshake, LatencyNS: 2_000_000, PID: 8, ProcessName: "curl", Error: -1},
			{Type: events.EventTLSHandshake, LatencyNS: 2_000_000, PID: 9, Error: -1},
		},
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}
	got := GenerateTLSSection(d, time.Second)
	for _, want := range []string{"TLS Statistics", "Total handshakes: 4", "Failed handshakes: 3 (75.0%)",
		"curl (2 failed)", "pid 9 (1 failed)", "Max latency: 4.00ms"} {
		if !strings.Contains(got, want) {
			t.Errorf("section lacks %q:\n%s", want, got)
		}
	}
}

func TestASessionWithoutTLSHasNoTLSSection(t *testing.T) {
	d := &mockDiagnostician{events: []*events.Event{{Type: events.EventDNS}}, startTime: time.Now(), endTime: time.Now().Add(time.Second)}
	if got := GenerateTLSSection(d, time.Second); got != "" {
		t.Errorf("got %q", got)
	}
}
