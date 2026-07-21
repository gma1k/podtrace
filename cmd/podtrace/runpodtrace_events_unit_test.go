package main

import (
	"context"
	"testing"

	"github.com/podtrace/podtrace/internal/ebpf"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/kubernetes"
	"github.com/podtrace/podtrace/internal/system"
)

type eventEmittingTracer struct {
	mockTracer
}

func (e *eventEmittingTracer) Start(ctx context.Context, ch chan<- *events.Event) error {
	go func() {
		for i := 0; i < 5; i++ {
			ev := &events.Event{Type: events.EventDNS}
			if i%2 == 1 {
				ev = &events.Event{Type: events.EventConnect}
			}
			select {
			case ch <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()
	return nil
}

var _ ebpf.TracerInterface = (*eventEmittingTracer)(nil)

func TestRunPodtrace_DiagnoseEventsFlowThroughConsumers(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()
	t.Setenv("PODTRACE_ALLOW_BROAD_CGROUP", "1")
	t.Setenv(system.EnvSkipLockdownCheck, "1")
	t.Setenv("PODTRACE_K8S_ENRICHMENT_ENABLED", "true")

	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return &mockPodResolverWithClientset{}, nil
	}
	tracerFactory = func() (ebpf.TracerInterface, error) {
		return &eventEmittingTracer{}, nil
	}
	enableMetrics = true
	enableTracing = true
	eventFilter = "dns,net"
	diagnoseDuration = "150ms"

	if err := runPodtraceUntilDone(t, cmdWithNamespaceChanged()); err != nil {
		t.Fatalf("expected diagnose completion with flowing events, got %v", err)
	}
}
