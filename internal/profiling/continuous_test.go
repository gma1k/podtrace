package profiling

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

type namingResolver struct {
	mu    sync.Mutex
	calls int
}

func namingFactory(r FrameResolver) func() FrameResolver {
	return func() FrameResolver { return r }
}

func (r *namingResolver) Resolve(_ context.Context, _ uint32, addr uint64) string {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	return fmt.Sprintf("fn_%x", addr)
}

func schedSample(namespace, workload string, pid uint32, stack ...uint64) *events.Event {
	return &events.Event{
		Type:  events.EventSchedSwitch,
		PID:   pid,
		Stack: stack,
		K8s: &events.K8sMetadata{
			Namespace:    namespace,
			WorkloadName: workload,
			WorkloadKind: "Deployment",
		},
	}
}

func TestContinuousProfilerCountsSchedSwitchStacksPerWorkload(t *testing.T) {
	p := NewContinuousProfiler(namingFactory(&namingResolver{}), nil)

	if err := p.Export(context.Background(), []*events.Event{
		schedSample("shop", "checkout", 1, 0x100, 0x200),
		schedSample("shop", "checkout", 1, 0x100, 0x300),
		schedSample("shop", "cart", 2, 0x400),
	}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	got := p.Snapshot(context.Background())
	if len(got) != 2 {
		t.Fatalf("expected two workloads, got %d", len(got))
	}
	if got[0].Workload != "checkout" {
		t.Errorf("expected the busiest workload first, got %q", got[0].Workload)
	}
	if got[0].Samples != 4 {
		t.Errorf("expected 4 samples for checkout, got %d", got[0].Samples)
	}
	if got[0].Frames[0].Frame != "fn_100" {
		t.Errorf("expected the repeated frame to rank first, got %q", got[0].Frames[0].Frame)
	}
}

func TestContinuousProfilerIgnoresEventsThatAreNotSchedSwitch(t *testing.T) {
	p := NewContinuousProfiler(namingFactory(&namingResolver{}), nil)
	_ = p.Export(context.Background(), []*events.Event{
		{Type: events.EventTCPSend, Stack: []uint64{0x100}, K8s: &events.K8sMetadata{
			Namespace: "shop", WorkloadName: "checkout"}},
	})
	if got := p.Snapshot(context.Background()); len(got) != 0 {
		t.Errorf("a non-sched-switch event was profiled: %v", got)
	}
}

func TestContinuousProfilerIgnoresUnattributedSamples(t *testing.T) {
	p := NewContinuousProfiler(namingFactory(&namingResolver{}), nil)
	_ = p.Export(context.Background(), []*events.Event{
		{Type: events.EventSchedSwitch, Stack: []uint64{0x100}},
		{Type: events.EventSchedSwitch, Stack: []uint64{0x100}, K8s: &events.K8sMetadata{}},
	})
	if got := p.Snapshot(context.Background()); len(got) != 0 {
		t.Errorf("a sample with no workload was profiled: %v", got)
	}
}

func TestContinuousProfilerSkipsNullFramesAndNilEvents(t *testing.T) {
	p := NewContinuousProfiler(namingFactory(&namingResolver{}), nil)
	_ = p.Export(context.Background(), []*events.Event{
		nil,
		schedSample("shop", "checkout", 1, 0, 0x100, 0),
	})

	got := p.Snapshot(context.Background())
	if len(got) != 1 {
		t.Fatalf("expected one workload, got %d", len(got))
	}
	if got[0].Samples != 1 {
		t.Errorf("zero addresses were counted as samples: %d", got[0].Samples)
	}
}

func TestContinuousProfilerStopsAtTheStackDepthCap(t *testing.T) {
	p := NewContinuousProfiler(namingFactory(&namingResolver{}), nil)

	deep := make([]uint64, maxCorrelatedStackDepth*2)
	for i := range deep {
		deep[i] = uint64(0x1000 + i)
	}
	_ = p.Export(context.Background(), []*events.Event{schedSample("shop", "checkout", 1, deep...)})

	got := p.Snapshot(context.Background())
	if len(got) != 1 {
		t.Fatalf("expected one workload, got %d", len(got))
	}
	if got[0].Samples != maxCorrelatedStackDepth {
		t.Errorf("expected the stack truncated to %d frames, got %d samples",
			maxCorrelatedStackDepth, got[0].Samples)
	}
}

func TestContinuousProfilerBoundsTheNumberOfWorkloads(t *testing.T) {
	p := NewContinuousProfiler(namingFactory(&namingResolver{}), nil)

	var batch []*events.Event
	for i := 0; i < maxProfiledWorkloads+50; i++ {
		batch = append(batch, schedSample("shop", fmt.Sprintf("workload-%d", i), uint32(i), 0x100))
	}
	_ = p.Export(context.Background(), batch)

	if got := len(p.Snapshot(context.Background())); got != maxProfiledWorkloads {
		t.Errorf("expected the workload map capped at %d, got %d", maxProfiledWorkloads, got)
	}
	if p.Dropped() == 0 {
		t.Error("workloads were refused without being counted as dropped")
	}
}

func TestContinuousProfilerBoundsFramesPerWorkload(t *testing.T) {
	p := NewContinuousProfiler(namingFactory(&namingResolver{}), nil)

	var batch []*events.Event
	for i := 0; i < maxFramesPerWorkload+100; i++ {
		batch = append(batch, schedSample("shop", "checkout", 1, uint64(0x10000+i)))
	}
	_ = p.Export(context.Background(), batch)

	if p.Dropped() == 0 {
		t.Error("distinct frames grew past the per-workload cap without being counted")
	}
	if got := p.Snapshot(context.Background())[0].Samples; got > maxFramesPerWorkload {
		t.Errorf("held %d samples against a %d cap", got, maxFramesPerWorkload)
	}
}

func TestContinuousProfilerAgesOutOldSamples(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	p := NewContinuousProfiler(namingFactory(&namingResolver{}), nil)
	p.now = func() time.Time { return now }
	p.rotatedAt = now

	_ = p.Export(context.Background(), []*events.Event{schedSample("shop", "checkout", 1, 0x100)})

	now = now.Add(defaultProfileWindow + time.Second)
	_ = p.Export(context.Background(), []*events.Event{schedSample("shop", "checkout", 1, 0x200)})
	if got := p.Snapshot(context.Background()); len(got) != 1 || got[0].Samples != 2 {
		t.Fatalf("after one rotation both halves should still count: %+v", got)
	}

	now = now.Add(defaultProfileWindow + time.Second)
	_ = p.Export(context.Background(), []*events.Event{schedSample("shop", "checkout", 1, 0x300)})

	got := p.Snapshot(context.Background())
	if len(got) != 1 {
		t.Fatalf("expected one workload, got %d", len(got))
	}
	if got[0].Samples != 2 {
		t.Errorf("the oldest half-window was not discarded: %d samples", got[0].Samples)
	}
	for _, f := range got[0].Frames {
		if f.Frame == "fn_100" {
			t.Error("a sample two windows old is still being reported")
		}
	}
}

func TestContinuousProfilerSymbolisesOnlyAtSnapshot(t *testing.T) {
	r := &namingResolver{}
	p := NewContinuousProfiler(namingFactory(r), nil)

	var batch []*events.Event
	for i := 0; i < 500; i++ {
		batch = append(batch, schedSample("shop", "checkout", 1, 0x100))
	}
	_ = p.Export(context.Background(), batch)

	if r.calls != 0 {
		t.Fatalf("the resolver was called %d times on the event path", r.calls)
	}
	p.Snapshot(context.Background())
	if r.calls == 0 {
		t.Error("the resolver was never called at snapshot time")
	}
	if r.calls > maxSymbolizedFrames {
		t.Errorf("symbolised %d frames against a %d cap", r.calls, maxSymbolizedFrames)
	}
}

func TestContinuousProfilerReportsHexWithoutAResolver(t *testing.T) {
	p := NewContinuousProfiler(nil, nil)
	_ = p.Export(context.Background(), []*events.Event{schedSample("shop", "checkout", 1, 0xdead)})

	got := p.Snapshot(context.Background())
	if len(got) != 1 || len(got[0].Frames) != 1 {
		t.Fatalf("expected one frame, got %+v", got)
	}
	if got[0].Frames[0].Frame != "0xdead" {
		t.Errorf("expected a hex frame with no resolver, got %q", got[0].Frames[0].Frame)
	}
}

func TestContinuousProfilerIsSafeWhenNil(t *testing.T) {
	var p *ContinuousProfiler
	if err := p.Export(context.Background(), []*events.Event{schedSample("a", "b", 1, 0x1)}); err != nil {
		t.Errorf("Export on a nil profiler: %v", err)
	}
	if got := p.Snapshot(context.Background()); got != nil {
		t.Errorf("Snapshot on a nil profiler returned %v", got)
	}
	if got := p.Dropped(); got != 0 {
		t.Errorf("Dropped on a nil profiler returned %d", got)
	}
}

func TestContinuousProfilerNameAndCloseSatisfyTheExporterContract(t *testing.T) {
	p := NewContinuousProfiler(nil, nil)
	if p.Name() == "" {
		t.Error("the exporter has no name")
	}
	if err := p.Close(context.Background()); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestContinuousProfilerOrdersEquallyBusyWorkloadsDeterministically(t *testing.T) {
	p := NewContinuousProfiler(namingFactory(&namingResolver{}), nil)
	_ = p.Export(context.Background(), []*events.Event{
		schedSample("zeta", "same", 1, 0x100),
		schedSample("alpha", "same", 2, 0x200),
		schedSample("middle", "same", 3, 0x300),
	})

	first := p.Snapshot(context.Background())
	if len(first) != 3 {
		t.Fatalf("expected three workloads, got %d", len(first))
	}
	want := []string{"alpha", "middle", "zeta"}
	for i, ns := range want {
		if first[i].Namespace != ns {
			t.Errorf("position %d is %q, want %q; equally busy workloads must not be "+
				"ordered by map iteration", i, first[i].Namespace, ns)
		}
	}

	for range 5 {
		again := p.Snapshot(context.Background())
		for i := range again {
			if again[i].Namespace != first[i].Namespace {
				t.Fatalf("snapshot order changed between calls: %q then %q",
					first[i].Namespace, again[i].Namespace)
			}
		}
	}
}

func TestContinuousProfilerDropsAWorkloadWhoseSamplesAllAgedOut(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	p := NewContinuousProfiler(namingFactory(&namingResolver{}), nil)
	p.now = func() time.Time { return now }
	p.rotatedAt = now

	_ = p.Export(context.Background(), []*events.Event{schedSample("shop", "gone", 1, 0x100)})

	now = now.Add(defaultProfileWindow + time.Second)
	_ = p.Export(context.Background(), nil)
	now = now.Add(defaultProfileWindow + time.Second)
	_ = p.Export(context.Background(), nil)

	if got := p.Snapshot(context.Background()); len(got) != 0 {
		t.Errorf("a workload with nothing left in either half-window is still reported: %+v", got)
	}
}

func TestContinuousProfilerDoesNotReportAWorkloadWhoseStackWasAllZeroes(t *testing.T) {
	p := NewContinuousProfiler(namingFactory(&namingResolver{}), nil)
	_ = p.Export(context.Background(), []*events.Event{
		schedSample("shop", "checkout", 1, 0, 0, 0),
	})

	if got := p.Snapshot(context.Background()); len(got) != 0 {
		t.Errorf("a workload whose every frame was a null address was reported with "+
			"zero samples: %+v", got)
	}
}

func TestContinuousProfilerResolvesIdentityFromTheCgroupWhenEventsAreUnenriched(t *testing.T) {
	lookup := func(cgroupID uint64) (events.K8sMetadata, bool) {
		if cgroupID != 4242 {
			return events.K8sMetadata{}, false
		}
		return events.K8sMetadata{Namespace: "shop", WorkloadName: "checkout"}, true
	}
	p := NewContinuousProfiler(namingFactory(&namingResolver{}), lookup)

	_ = p.Export(context.Background(), []*events.Event{
		{Type: events.EventSchedSwitch, PID: 1, CgroupID: 4242, Stack: []uint64{0x100}},
	})

	got := p.Snapshot(context.Background())
	if len(got) != 1 {
		t.Fatalf("an unenriched event was dropped; agent events carry no K8s metadata, "+
			"so reading e.K8s alone profiles nothing at all. got %d workloads", len(got))
	}
	if got[0].Namespace != "shop" || got[0].Workload != "checkout" {
		t.Errorf("identity = %s/%s, want shop/checkout", got[0].Namespace, got[0].Workload)
	}
}

func TestContinuousProfilerDropsAnEventNoLookupCanAttribute(t *testing.T) {
	p := NewContinuousProfiler(namingFactory(&namingResolver{}), func(uint64) (events.K8sMetadata, bool) {
		return events.K8sMetadata{}, false
	})
	_ = p.Export(context.Background(), []*events.Event{
		{Type: events.EventSchedSwitch, PID: 1, CgroupID: 9, Stack: []uint64{0x100}},
	})
	if got := p.Snapshot(context.Background()); len(got) != 0 {
		t.Errorf("an unattributable event was profiled: %+v", got)
	}
}

func TestContinuousProfilerPrefersMetadataAlreadyOnTheEvent(t *testing.T) {
	p := NewContinuousProfiler(namingFactory(&namingResolver{}), func(uint64) (events.K8sMetadata, bool) {
		return events.K8sMetadata{Namespace: "wrong", WorkloadName: "wrong"}, true
	})
	_ = p.Export(context.Background(), []*events.Event{schedSample("shop", "checkout", 1, 0x100)})

	got := p.Snapshot(context.Background())
	if len(got) != 1 || got[0].Namespace != "shop" {
		t.Errorf("the lookup overrode metadata already on the event: %+v", got)
	}
}

func TestContinuousProfilerDropsALookupThatReturnsNoWorkload(t *testing.T) {
	p := NewContinuousProfiler(namingFactory(&namingResolver{}), func(uint64) (events.K8sMetadata, bool) {
		return events.K8sMetadata{Namespace: "shop"}, true
	})
	_ = p.Export(context.Background(), []*events.Event{
		{Type: events.EventSchedSwitch, PID: 1, CgroupID: 7, Stack: []uint64{0x100}},
	})
	if got := p.Snapshot(context.Background()); len(got) != 0 {
		t.Errorf("a lookup hit carrying no workload name was profiled as %+v; a series "+
			"keyed on an empty workload cannot be attributed to anything", got)
	}
}

func TestContinuousProfilerDropsAnEventWhoseOwnMetadataIsHalfEmpty(t *testing.T) {
	p := NewContinuousProfiler(namingFactory(&namingResolver{}), nil)
	_ = p.Export(context.Background(), []*events.Event{
		{Type: events.EventSchedSwitch, PID: 1, Stack: []uint64{0x100},
			K8s: &events.K8sMetadata{Namespace: "shop"}},
	})
	if got := p.Snapshot(context.Background()); len(got) != 0 {
		t.Errorf("an event with a namespace but no workload was profiled: %+v", got)
	}
}
