package tracer

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/analysis/criticalpath"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/procfs"
	"github.com/gma1k/podtrace/internal/redactor"
)

func withProcComm(t *testing.T, pid, comm string) {
	t.Helper()
	root := t.TempDir()
	if comm != "" {
		if err := os.MkdirAll(filepath.Join(root, pid), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, pid, "comm"), []byte(comm+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	previous := config.ProcBasePath
	config.SetProcBasePath(root)
	procfs.ResetForTesting()
	t.Cleanup(func() {
		config.SetProcBasePath(previous)
		procfs.ResetForTesting()
	})
}

func dispatchInto(ctx context.Context, tr *Tracer, ev *events.Event, ch chan *events.Event) {
	var collected, filtered, parsed atomic.Int64
	var filteringDisabled atomic.Bool
	tr.processAndDispatch(ctx, ev, ch, nil, &eventCounters{
		collected: &collected, filtered: &filtered, parsed: &parsed, filteringDisabled: &filteringDisabled,
	}, time.Now())
}

func receive(ch chan *events.Event) *events.Event {
	select {
	case e := <-ch:
		return e
	default:
		return nil
	}
}

func TestATransientCommIsReplacedByTheProcessRealName(t *testing.T) {
	withProcComm(t, "4321", "nginx")
	ch := make(chan *events.Event, 1)
	dispatchInto(context.Background(), newDispatchTestTracer(), &events.Event{Type: events.EventTCPSend, PID: 4321, ProcessName: "1"}, ch)

	if e := receive(ch); e == nil || e.ProcessName != "nginx" {
		t.Errorf("got %+v, want ProcessName nginx: a one-digit comm is runc's bootstrap "+
			"placeholder, and the process's own comm names what actually ran", e)
	}
}

func TestAnUnresolvableTransientCommIsLabelledAsBootstrap(t *testing.T) {
	withProcComm(t, "4321", "")
	ch := make(chan *events.Event, 1)
	dispatchInto(context.Background(), newDispatchTestTracer(), &events.Event{Type: events.EventTCPSend, PID: 4321, ProcessName: "1"}, ch)

	if e := receive(ch); e == nil || e.ProcessName != "runc-bootstrap[1]" {
		t.Errorf("got %+v, want runc-bootstrap[1] when the process is already gone", e)
	}
}

func TestRedactionAndCriticalPathSeeEveryDispatchedEvent(t *testing.T) {
	tr := newDispatchTestTracer()
	tr.piiRedactor = redactor.New([]redactor.Rule{{Name: "secret", Pattern: regexp.MustCompile(`s3cr3t`), Replace: "[redacted]"}})
	tr.cpAnalyzer = criticalpath.New(time.Minute, func(criticalpath.CriticalPath) {})
	ch := make(chan *events.Event, 1)

	dispatchInto(context.Background(), tr, &events.Event{Type: events.EventHTTPResp, PID: 7, Target: "/login?pw=s3cr3t", Error: 500}, ch)

	e := receive(ch)
	if e == nil {
		t.Fatal("the event was not delivered")
	}
	if e.Target != "/login?pw=[redacted]" {
		t.Errorf("Target = %q, want the secret redacted before the event leaves the tracer", e.Target)
	}
}

func TestWithNoFilteringConfiguredEveryEventIsAdmitted(t *testing.T) {
	ch := make(chan *events.Event, 1)
	dispatchInto(context.Background(), newDispatchTestTracer(), &events.Event{Type: events.EventTCPSend, PID: 99}, ch)
	if receive(ch) == nil {
		t.Error("with no targets and no deny mode, an event was dropped")
	}
}

func TestACancelledTracerDoesNotDeliver(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ch := make(chan *events.Event)
	done := make(chan struct{})
	go func() {
		dispatchInto(ctx, newDispatchTestTracer(), &events.Event{Type: events.EventTCPSend, PID: 99}, ch)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("dispatch blocked on a consumer after its context was cancelled")
	}
}

func TestAFullChannelIsReportedAsADrop(t *testing.T) {
	tr := newDispatchTestTracer()
	var reason string
	tr.SetDropReporter(func(r string, _ int) { reason = r })
	ch := make(chan *events.Event, 1)
	ch <- &events.Event{}

	dispatchInto(context.Background(), tr, &events.Event{Type: events.EventTCPSend, PID: 99}, ch)
	if reason != "channel_full" {
		t.Errorf("drop reason = %q, want channel_full: an event lost to a full channel must be counted, not vanish", reason)
	}
}
