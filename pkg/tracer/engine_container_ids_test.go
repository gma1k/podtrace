package tracer_test

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/podtrace/podtrace/pkg/tracer"
)

type containerIDsBackend struct {
	*mockBackend
	rmu        sync.Mutex
	setCalls   [][]string
	perIDCalls int
}

func (b *containerIDsBackend) SetContainerIDs(ids []string) error {
	b.rmu.Lock()
	defer b.rmu.Unlock()
	b.setCalls = append(b.setCalls, append([]string(nil), ids...))
	return nil
}

func (b *containerIDsBackend) SetContainerID(_ string) error {
	b.rmu.Lock()
	defer b.rmu.Unlock()
	b.perIDCalls++
	return nil
}

func TestEngine_FallbackBackendGetsFullContainerIDSet(t *testing.T) {
	backend := &containerIDsBackend{mockBackend: &mockBackend{}}
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
		backend.rmu.Lock()
		defer backend.rmu.Unlock()
		return len(backend.setCalls) == 1
	})

	backend.rmu.Lock()
	got := append([]string(nil), backend.setCalls[0]...)
	perID := backend.perIDCalls
	backend.rmu.Unlock()
	sort.Strings(got)
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("SetContainerIDs got %v, want [a b] in one call", got)
	}
	if perID != 0 {
		t.Errorf("SetContainerID called %d times, want 0 (set-based call must be preferred)", perID)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned: %v", err)
	}
}
