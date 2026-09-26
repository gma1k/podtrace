package report

import (
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
)

func TestTheConnectionSectionSeparatesANoRouteFallback(t *testing.T) {
	d := &filterDiagnostician{
		byType: map[events.EventType][]*events.Event{
			events.EventConnect: {
				{Type: events.EventConnect, Error: -101, Target: "[2001:db8::1]:80"},
				{Type: events.EventConnect, Error: -101, Target: "[2001:db8::2]:80"},
				{Type: events.EventConnect, LatencyNS: 40_000, Target: "142.250.1.1:80"},
			},
			events.EventConnectResult: {
				{Type: events.EventConnectResult, Target: "142.250.1.1:80"},
			},
		},
		startTime: time.Unix(0, 0),
		endTime:   time.Unix(10, 0),
	}
	section := GenerateConnectionSection(d, 10*time.Second)
	if !strings.Contains(section, "Failed connections: 0 of 1 attempts") {
		t.Errorf("the IPv6 fallback was scored as failed attempts:\n%s", section)
	}
	if !strings.Contains(section, "No route for address family: 2") {
		t.Errorf("the fallback was not reported on its own line:\n%s", section)
	}
}

func TestPercentileMsInterpolatesAndHandlesTheEdges(t *testing.T) {
	sorted := []uint64{1_000_000, 2_000_000, 3_000_000, 4_000_000}
	for _, tc := range []struct {
		name string
		in   []uint64
		p    int
		want float64
	}{
		{"empty", nil, 50, 0},
		{"single", []uint64{7_000_000}, 99, 7},
		{"p0", sorted, 0, 1},
		{"p100", sorted, 100, 4},
		{"p50 interpolates", sorted, 50, 2.5},
		{"p99 stays below the max", sorted, 99, 3.97},
	} {
		if got := percentileMs(tc.in, tc.p); got < tc.want-1e-9 || got > tc.want+1e-9 {
			t.Errorf("%s: percentileMs = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestBurstsBeyondTheDisplayLimitAreNotListed(t *testing.T) {
	var evs []*events.Event
	for _, second := range []uint64{0, 20, 40, 60, 80} {
		for j := uint64(0); j < 20; j++ {
			evs = append(evs, &events.Event{Type: events.EventTCPSend, Timestamp: second*1_000_000_000 + j})
		}
	}
	out := formatBursts(evs, time.Unix(0, 0), 100*time.Second)
	if !strings.Contains(out, "Detected 5 burst period(s)") {
		t.Fatalf("expected five bursts from five dense seconds:\n%s", out)
	}
	if got := strings.Count(out, "events/sec"); got != config.MaxBurstsDisplay {
		t.Errorf("listed %d bursts, want the display limit of %d", got, config.MaxBurstsDisplay)
	}
}
