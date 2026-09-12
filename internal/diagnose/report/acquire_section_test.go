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

func TestNoLeakWarningWhenThereAreNoClientLibraryEvents(t *testing.T) {
	d := &mockDiagnostician{events: []*events.Event{
		acquireWaitEvent(300), acquireWaitEvent(400),
	}}

	got := GeneratePoolSection(d, time.Minute)

	if strings.Contains(got, "possible leak") {
		t.Errorf("a leak warning for a workload that acquired nothing:\n%s\n\n"+
			"determinePoolHealth reads a release ratio computed from zero acquires and "+
			"zero releases. Rendering it for Go database/sql, which emits neither, "+
			"accuses the workload of leaking connections it never took.", got)
	}
	if strings.Contains(got, "Total acquires: 0") {
		t.Errorf("client-library counters rendered with nothing behind them:\n%s", got)
	}
	if !strings.Contains(got, "Connection acquisition") {
		t.Errorf("the acquisition subsection went missing:\n%s", got)
	}
}

func TestClientLibraryCountersStillRenderWhenThatPathSawEvents(t *testing.T) {
	d := &mockDiagnostician{events: []*events.Event{
		{Type: events.EventPoolAcquire},
		{Type: events.EventPoolAcquire},
		{Type: events.EventPoolRelease},
	}}

	got := GeneratePoolSection(d, time.Minute)

	if !strings.Contains(got, "Total acquires: 2") {
		t.Errorf("the client-library counters vanished for a workload that does emit them:\n%s", got)
	}
	if !strings.Contains(got, "Status:") {
		t.Errorf("the health verdict vanished:\n%s", got)
	}
}

func TestExhaustionFiguresAreNamedConsistentlyEverywhere(t *testing.T) {
	d := &mockDiagnostician{events: []*events.Event{
		{Type: events.EventPoolAcquire},
		{Type: events.EventPoolRelease},
		{Type: events.EventPoolExhausted, LatencyNS: 100_000_000},
	}}

	got := GeneratePoolSection(d, time.Minute)

	if strings.Contains(got, "wait time") {
		t.Errorf("the report still calls a connection age a wait time:\n%s\n\nThe "+
			"client-library probe timestamps a connection when it is acquired and never "+
			"refreshes it, so the figure is how long the connection had been held. The "+
			"section carries a real queue time right below it, and two different numbers "+
			"sharing one name is how an operator reads the wrong one.", got)
	}
	if n := strings.Count(got, "connection age at query"); n < 2 {
		t.Errorf("only %d of the two blocks name it as a connection age:\n%s\n\nThe "+
			"per-pool block renders the same figure as the summary above it, so the two "+
			"drifting apart puts both names in one report.", n, got)
	}
}
