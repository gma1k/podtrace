package report

import (
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

func poolSectionFrom(byType map[events.EventType][]*events.Event) string {
	return GeneratePoolSection(&filterDiagnostician{
		byType:    byType,
		startTime: time.Now(),
		endTime:   time.Now().Add(time.Second),
	}, time.Second)
}

func TestPoolCapacityIsReportedAgainstItsLimit(t *testing.T) {
	got := poolSectionFrom(map[events.EventType][]*events.Event{
		events.EventDBPoolStats: {
			{Type: events.EventDBPoolStats, Bytes: 4, TCPState: 20, Error: 20},
			{Type: events.EventDBPoolStats, Bytes: 19, TCPState: 20, Error: 95},
		},
	})

	for _, want := range []string{
		"Pool capacity (Go database/sql):",
		"Samples: 2",
		"Peak connections open: 19 of 20 (95% utilized)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestAnUnlimitedPoolIsNotReportedAsZeroPercent(t *testing.T) {
	got := poolSectionFrom(map[events.EventType][]*events.Event{
		events.EventDBPoolStats: {
			{Type: events.EventDBPoolStats, Bytes: 41, TCPState: 0, Error: 0},
		},
	})

	if !strings.Contains(got, "Peak connections open: 41 (SetMaxOpenConns unlimited)") {
		t.Errorf("unlimited pool not named as such:\n%s", got)
	}
	if strings.Contains(got, "utilized") {
		t.Errorf("a utilization was claimed against a pool with no ceiling:\n%s", got)
	}
}

func TestAStrippedBinaryIsToldWhyCapacityIsMissing(t *testing.T) {
	got := poolSectionFrom(map[events.EventType][]*events.Event{
		events.EventDBAcquire: {
			{Type: events.EventDBAcquire, LatencyNS: 5_000_000},
		},
	})

	if strings.Contains(got, "Pool capacity") && !strings.Contains(got, "DWARF") {
		t.Fatalf("a capacity block was rendered without samples:\n%s", got)
	}
	if !strings.Contains(got, "-ldflags=-w strips") {
		t.Errorf("an operator seeing acquisition waits but no capacity gets no reason for "+
			"the hole:\n%s", got)
	}
}

func TestCapacityAloneStillRendersTheSection(t *testing.T) {
	got := poolSectionFrom(map[events.EventType][]*events.Event{
		events.EventDBPoolStats: {
			{Type: events.EventDBPoolStats, Bytes: 6, TCPState: 10, Error: 60},
		},
	})

	if !strings.Contains(got, "Connection Pool") {
		t.Errorf("no section header:\n%s", got)
	}
	if !strings.Contains(got, "Peak connections open: 6 of 10 (60% utilized)") {
		t.Errorf("a workload whose only pool evidence is capacity reported nothing:\n%s", got)
	}
}

func TestCapacityIsSeparatedFromTheAcquisitionBlock(t *testing.T) {
	got := poolSectionFrom(map[events.EventType][]*events.Event{
		events.EventDBAcquire: {
			{Type: events.EventDBAcquire, LatencyNS: 5_000_000},
		},
		events.EventDBPoolStats: {
			{Type: events.EventDBPoolStats, Bytes: 19, TCPState: 20, Error: 95},
		},
	})

	if strings.Contains(got, "-ldflags=-w strips") {
		t.Errorf("the missing-DWARF note was printed beside a capacity block:\n%s", got)
	}
	if !strings.Contains(got, "\n\nPool capacity (Go database/sql):") {
		t.Errorf("capacity runs into the acquisition block:\n%s", got)
	}
}
