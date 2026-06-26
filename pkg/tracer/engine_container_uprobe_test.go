package tracer_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/podtrace/podtrace/pkg/tracer"
)

type reconcilerBackend struct {
	*mockBackend
	rmu         sync.Mutex
	lastTargets []tracer.ContainerUprobeTarget
	calls       int
}

func (r *reconcilerBackend) SetContainerTargets(targets []tracer.ContainerUprobeTarget) error {
	r.rmu.Lock()
	defer r.rmu.Unlock()
	r.lastTargets = append([]tracer.ContainerUprobeTarget(nil), targets...)
	r.calls++
	return nil
}

func (r *reconcilerBackend) targetsByID() map[string]uint32 {
	r.rmu.Lock()
	defer r.rmu.Unlock()
	m := make(map[string]uint32, len(r.lastTargets))
	for _, t := range r.lastTargets {
		m[t.ContainerID] = t.PID
	}
	return m
}

func TestEngine_DrivesContainerUprobeReconciler(t *testing.T) {
	backend := &reconcilerBackend{mockBackend: &mockBackend{}}
	exporter := &recordingExporter{name: "rec"}
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{exporter}, tracer.Config{EventBufferSize: 16, ExportBatchSize: 4})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	targets := make(chan tracer.TargetSet, 4)
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, targets) }()

	targets <- tracer.TargetSet{
		{CgroupPath: "/cg/a", ContainerID: "a", ContainerPID: 111},
		{CgroupPath: "/cg/b", ContainerID: "b", ContainerPID: 222},
	}
	waitUntil(t, 2*time.Second, func() bool {
		m := backend.targetsByID()
		return m["a"] == 111 && m["b"] == 222
	})

	targets <- tracer.TargetSet{
		{CgroupPath: "/cg/a", ContainerID: "a", ContainerPID: 111},
		{CgroupPath: "/cg/c", ContainerID: "c", ContainerPID: 333},
	}
	waitUntil(t, 2*time.Second, func() bool {
		m := backend.targetsByID()
		_, hasB := m["b"]
		return m["a"] == 111 && m["c"] == 333 && !hasB
	})

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned: %v", err)
	}
}