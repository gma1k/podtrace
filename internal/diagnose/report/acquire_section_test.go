package report

import (
	"strings"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

func acquireWaitEvent(ms int) *events.Event {
	return &events.Event{
		Type:      events.EventDBAcquire,
		LatencyNS: uint64(ms) * 1_000_000,
	}
}

func TestPoolSectionRendersForAGoAppWithNoClientLibraryEvents(t *testing.T) {
	d := &mockDiagnostician{events: []*events.Event{
		acquireWaitEvent(120), acquireWaitEvent(480), acquireWaitEvent(900),
	}}

	got := GeneratePoolSection(d, time.Minute)

	if got == "" {
		t.Fatal("no pool section for a workload whose only pool signal is acquisition " +
			"waits.\n\nGo database/sql emits no acquire/release events -- those come from " +
			"the C client-library probes -- so keying the section on them hid the pool " +
			"from exactly the runtime whose pool is instrumented best. The operator sees " +
			"off-CPU blocking and nothing naming the cause.")
	}
	if !strings.Contains(got, "Connection acquisition") {
		t.Errorf("section has no acquisition subsection:\n%s", got)
	}
	if !strings.Contains(got, "Blocking acquisitions: 3") {
		t.Errorf("acquisition count missing from:\n%s", got)
	}
}

func TestPoolSectionStaysEmptyWhenNothingTouchedAPool(t *testing.T) {
	d := &mockDiagnostician{events: []*events.Event{
		{Type: events.EventTCPSend, LatencyNS: 1_000_000},
	}}

	if got := GeneratePoolSection(d, time.Minute); got != "" {
		t.Errorf("rendered a pool section for a workload with no pool activity:\n%s", got)
	}
}

func TestAcquisitionSubsectionNamesWhatItCannotDistinguish(t *testing.T) {
	d := &mockDiagnostician{events: []*events.Event{acquireWaitEvent(250)}}

	got := GeneratePoolSection(d, time.Minute)

	if !strings.Contains(got, "DBStats") {
		t.Errorf("the subsection never points at sql.DBStats:\n%s\n\nThe probe cannot "+
			"separate queueing for a slot from establishing a connection, and DBStats "+
			"counts only the first. Without that pointer the reader has no way to tell "+
			"which of the two they are looking at.", got)
	}
	if !strings.Contains(got, "queueing") || !strings.Contains(got, "establishing") {
		t.Errorf("the subsection does not name both causes:\n%s", got)
	}
}

func TestAcquisitionWaitsDoNotOverwriteExhaustionWaits(t *testing.T) {
	d := &mockDiagnostician{events: []*events.Event{
		{Type: events.EventPoolAcquire},
		{Type: events.EventPoolRelease},
		{Type: events.EventPoolExhausted, LatencyNS: 9_000_000_000},
		acquireWaitEvent(50),
	}}

	got := GeneratePoolSection(d, time.Minute)

	if !strings.Contains(got, "Pool exhaustion events") {
		t.Errorf("the client-library exhaustion figures vanished:\n%s", got)
	}
	if !strings.Contains(got, "Connection acquisition") {
		t.Errorf("the acquisition figures vanished:\n%s", got)
	}
}
