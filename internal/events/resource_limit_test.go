package events

import (
	"strings"
	"testing"

	"github.com/podtrace/podtrace/internal/config"
)

// TestFormatMessage_ResourceLimit_NegativeErrorIsDropped: the
// EventResourceLimit branch treats e.Error as a percentage; a negative
// value (which can't represent a real utilization) must produce no
// output rather than wrap to a huge uint when narrowed.
func TestFormatMessage_ResourceLimit_NegativeErrorIsDropped(t *testing.T) {
	ev := &Event{Type: EventResourceLimit, TCPState: 0, Error: -1}
	if got := ev.FormatMessage(); got != "" {
		t.Errorf("expected empty message for negative utilization, got %q", got)
	}
}

// TestFormatMessage_ResourceLimit_BoundaryThresholds locks in the
// inclusive >= comparison at every tier boundary.
func TestFormatMessage_ResourceLimit_BoundaryThresholds(t *testing.T) {
	cases := []struct {
		err  int32
		want string // substring expected; empty == no output
	}{
		// Below warn → no output.
		{int32(config.AlertWarnPct - 1), ""},
		// At warn → WARNING.
		{int32(config.AlertWarnPct), "WARNING"},
		// At crit → CRITICAL.
		{int32(config.AlertCritPct), "CRITICAL"},
		// At emerg → EMERGENCY.
		{int32(config.AlertEmergPct), "EMERGENCY"},
		// 100 % → still EMERGENCY (>= AlertEmergPct).
		{100, "EMERGENCY"},
	}
	for _, c := range cases {
		ev := &Event{Type: EventResourceLimit, TCPState: 0, Error: c.err}
		got := ev.FormatMessage()
		if c.want == "" {
			if got != "" {
				t.Errorf("err=%d: expected empty, got %q", c.err, got)
			}
			continue
		}
		if !strings.Contains(got, c.want) {
			t.Errorf("err=%d: want substring %q, got %q", c.err, c.want, got)
		}
	}
}

// TestFormatMessage_ResourceLimit_UnknownResourceTypeFallsBack covers the
// default branch in the resource-name switch.
func TestFormatMessage_ResourceLimit_UnknownResourceTypeFallsBack(t *testing.T) {
	ev := &Event{Type: EventResourceLimit, TCPState: 99, Error: int32(config.AlertEmergPct)}
	got := ev.FormatMessage()
	if !strings.Contains(got, "Resource") {
		t.Errorf("default resource name should be 'Resource', got %q", got)
	}
}
