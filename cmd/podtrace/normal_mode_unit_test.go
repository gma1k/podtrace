package main

import (
	"context"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/kubernetes"
)

type fakeProfilingReporter struct {
	called bool
}

func (f *fakeProfilingReporter) GenerateSection(_ []*events.Event, _ time.Duration) string {
	f.called = true
	return "\n[profiling section]\n"
}

func TestRunNormalModeWithSource_ConsumesEventsThenReturnsOnCancel(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()

	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan *events.Event, 2)
	ch <- &events.Event{Type: events.EventDNS}

	reporter := &fakeProfilingReporter{}
	done := make(chan error, 1)
	go func() {
		done <- runNormalModeWithSource(ctx, ch, nil, nil, nil, nil, false, nil, reporter)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runNormalModeWithSource returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runNormalModeWithSource did not return after cancel")
	}
	if !reporter.called {
		t.Error("expected profiling reporter's GenerateSection to be invoked in the final report")
	}
}

func TestRunNormalMode_WrapperReturnsOnCancel(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()

	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan *events.Event)

	podInfo := &kubernetes.PodInfo{PodName: "p", Namespace: "default"}
	done := make(chan error, 1)
	go func() {
		done <- runNormalMode(ctx, ch, podInfo, nil, nil, nil, false)
	}()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runNormalMode returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runNormalMode did not return after cancel")
	}
}
