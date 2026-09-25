package profiling

import (
	"context"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/diagnose/stacktrace"
	"github.com/gma1k/podtrace/internal/events"
)

func resolvableBatch() []*events.Event {
	self := uint32(os.Getpid())
	addrs := []uint64{
		uint64(reflect.ValueOf(NewContinuousProfiler).Pointer()),
		uint64(reflect.ValueOf(symbolizeHotFrames).Pointer()),
		uint64(reflect.ValueOf(Correlate).Pointer()),
		uint64(reflect.ValueOf(GenerateSection).Pointer()),
	}
	var batch []*events.Event
	for i := 0; i < 40; i++ {
		batch = append(batch, schedSample("shop", "checkout", self, addrs[i%len(addrs)]+uint64(i)))
	}
	return batch
}

func TestConcurrentSnapshotsDoNotShareAResolver(t *testing.T) {
	p := NewContinuousProfiler(func() FrameResolver { return stacktrace.NewResolver() }, nil)
	_ = p.Export(context.Background(), resolvableBatch())

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.Snapshot(context.Background())
		}()
	}
	wg.Wait()
}

func TestSnapshotsResolveRealFramesToFunctionNames(t *testing.T) {
	p := NewContinuousProfiler(func() FrameResolver { return stacktrace.NewResolver() }, nil)
	_ = p.Export(context.Background(), resolvableBatch())

	got := p.Snapshot(context.Background())
	if len(got) != 1 || len(got[0].Frames) == 0 {
		t.Fatalf("expected one profiled workload with frames, got %+v", got)
	}
	var named bool
	for _, f := range got[0].Frames {
		if len(f.Frame) > 2 && f.Frame[:2] != "0x" {
			named = true
		}
	}
	if !named {
		t.Errorf("no frame resolved to a name: %+v", got[0].Frames)
	}
}

func TestEverySnapshotGetsAFreshResolver(t *testing.T) {
	var built atomic.Int32
	p := NewContinuousProfiler(func() FrameResolver {
		built.Add(1)
		return &namingResolver{}
	}, nil)
	_ = p.Export(context.Background(), []*events.Event{schedSample("shop", "checkout", 1, 0x100)})

	for i := 0; i < 3; i++ {
		p.Snapshot(context.Background())
	}
	if got := built.Load(); got != 3 {
		t.Errorf("built %d resolvers for 3 snapshots, want 3.\n\nA resolver is not safe "+
			"for concurrent use and its caches grow with every executable it sees; one "+
			"held for the agent's lifetime was both a crash and a leak.", got)
	}
}

type slowResolver struct {
	active  *atomic.Int32
	maxSeen *atomic.Int32
}

func (s slowResolver) Resolve(_ context.Context, _ uint32, addr uint64) string {
	n := s.active.Add(1)
	for {
		m := s.maxSeen.Load()
		if n <= m || s.maxSeen.CompareAndSwap(m, n) {
			break
		}
	}
	time.Sleep(2 * time.Millisecond)
	s.active.Add(-1)
	return "fn"
}

func TestSymbolisationRunsOneSnapshotAtATime(t *testing.T) {
	var active, maxSeen atomic.Int32
	p := NewContinuousProfiler(func() FrameResolver {
		return slowResolver{active: &active, maxSeen: &maxSeen}
	}, nil)
	_ = p.Export(context.Background(), []*events.Event{
		schedSample("shop", "checkout", 1, 0x100),
		schedSample("shop", "checkout", 1, 0x200),
	})

	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.Snapshot(context.Background())
		}()
	}
	wg.Wait()

	if got := maxSeen.Load(); got != 1 {
		t.Errorf("%d snapshots symbolised at once, want 1.\n\nParsing one large Go "+
			"binary allocates around 300 MiB; concurrent /profile requests parsing in "+
			"parallel multiply that and reach the agent's memory limit.", got)
	}
}
