package tracer_test

import (
	"context"
	"testing"
	"time"

	"github.com/podtrace/podtrace/pkg/tracer"
)

func (r *reconcilerBackend) callCount() int {
	r.rmu.Lock()
	defer r.rmu.Unlock()
	return r.calls
}

func TestEngine_ContainerIdentityChangeReconciles(t *testing.T) {
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
		{CgroupPath: "/cg/a", ContainerID: "a", ContainerPID: 0},
	}
	waitUntil(t, 2*time.Second, func() bool {
		_, ok := backend.targetsByID()["a"]
		return ok
	})

	targets <- tracer.TargetSet{
		{CgroupPath: "/cg/a", ContainerID: "a", ContainerPID: 111},
	}
	waitUntil(t, 2*time.Second, func() bool {
		return backend.targetsByID()["a"] == 111
	})

	targets <- tracer.TargetSet{
		{CgroupPath: "/cg/a", ContainerID: "a2", ContainerPID: 222},
	}
	waitUntil(t, 2*time.Second, func() bool {
		return backend.targetsByID()["a2"] == 222
	})

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned: %v", err)
	}
}

func TestEngine_IdenticalUpdateDoesNotReconcile(t *testing.T) {
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

	set := tracer.TargetSet{{CgroupPath: "/cg/a", ContainerID: "a", ContainerPID: 111}}
	targets <- set
	waitUntil(t, 2*time.Second, func() bool {
		return backend.targetsByID()["a"] == 111
	})
	afterFirst := backend.callCount()

	targets <- tracer.TargetSet{{CgroupPath: "/cg/a", ContainerID: "a", ContainerPID: 111}}
	waitUntil(t, 2*time.Second, func() bool { return backend.callCount() >= afterFirst })
	time.Sleep(50 * time.Millisecond)

	if got := backend.callCount(); got != afterFirst {
		t.Fatalf("identical update triggered %d extra reconcile(s), want 0", got-afterFirst)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned: %v", err)
	}
}
