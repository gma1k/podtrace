package profiling

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/ebpf/oncpu"
	"github.com/gma1k/podtrace/internal/events"
)

func cgroupLookup(byCgroup map[uint64]string) MetadataLookup {
	return func(cgroupID uint64) (events.K8sMetadata, bool) {
		wl, ok := byCgroup[cgroupID]
		if !ok {
			return events.K8sMetadata{}, false
		}
		return events.K8sMetadata{Namespace: "shop", WorkloadName: wl}, true
	}
}

func onCPUProfiler() *ContinuousProfiler {
	return NewContinuousProfiler(namingFactory(&namingResolver{}), cgroupLookup(map[uint64]string{7: "checkout", 8: "cart"}))
}

func TestOnCPUSamplesAreCountedByTheFunctionTheyWereRunning(t *testing.T) {
	p := onCPUProfiler()
	p.IngestOnCPU(oncpu.Drained{Samples: []oncpu.Sample{
		{CgroupID: 7, PID: 1, Stack: []uint64{0x100, 0x200}, Count: 30},
		{CgroupID: 7, PID: 1, Stack: []uint64{0x300, 0x200}, Count: 10},
		{CgroupID: 8, PID: 2, Stack: []uint64{0x400}, Count: 5},
	}})

	got := p.Snapshot(context.Background())
	if len(got) != 2 || got[0].Workload != "checkout" {
		t.Fatalf("profiles = %+v", got)
	}
	c := got[0]
	if c.Source != SourceOnCPU || c.Samples != 40 {
		t.Errorf("checkout = %d samples from %q, want 40 from on-cpu", c.Samples, c.Source)
	}
	want := []FrameCount{{Frame: "fn_100", Count: 30}, {Frame: "fn_300", Count: 10}}
	if len(c.Frames) != 2 || c.Frames[0] != want[0] || c.Frames[1] != want[1] {
		t.Errorf("frames = %+v, want self time %+v; the shared caller fn_200 ran nothing itself", c.Frames, want)
	}
	if p.Source() != SourceOnCPU {
		t.Errorf("Source = %q", p.Source())
	}
}

func TestTheFirstOnCPUDrainReplacesTheSchedSwitchStacks(t *testing.T) {
	p := onCPUProfiler()
	_ = p.Export(context.Background(), []*events.Event{schedSample("shop", "checkout", 1, 0x900)})
	p.IngestOnCPU(oncpu.Drained{Samples: []oncpu.Sample{{CgroupID: 7, PID: 1, Stack: []uint64{0x100}, Count: 1}}})
	_ = p.Export(context.Background(), []*events.Event{schedSample("shop", "checkout", 1, 0x900)})

	got := p.Snapshot(context.Background())
	if len(got) != 1 || got[0].Samples != 1 || got[0].Frames[0].Frame != "fn_100" {
		t.Errorf("profile = %+v; off-CPU and on-CPU stacks measure different things and must not be mixed", got)
	}
}

func TestOnCPUSchedulerFramesAreRealCPUAndStayVisible(t *testing.T) {
	p := NewContinuousProfiler(namingFactory(&fakeResolver{names: goServiceNames()}), cgroupLookup(map[uint64]string{7: "checkout"}))
	p.IngestOnCPU(oncpu.Drained{Samples: []oncpu.Sample{{CgroupID: 7, PID: 1, Stack: []uint64{0x10, 0x20, 0x50}, Count: 3}}})

	got := p.Snapshot(context.Background())[0]
	if got.SchedulerFrames != 0 || got.Frames[0].Count != 3 || isSchedulerFrame(got.Frames[0].Frame) == false {
		t.Errorf("profile = %+v; a scheduler spinning on a CPU is CPU the workload pays for", got)
	}
}

func TestOnCPUSamplesNoWorkloadOwnsAreIgnored(t *testing.T) {
	p := onCPUProfiler()
	p.IngestOnCPU(oncpu.Drained{Samples: []oncpu.Sample{
		{CgroupID: 99, PID: 1, Stack: []uint64{0x100}, Count: 4},
		{CgroupID: 7, PID: 1, Stack: []uint64{0}, Count: 4},
	}, Completions: []oncpu.Completion{{CgroupID: 99, CorrelationID: 1, LatencyNS: 5}}})
	if got := p.Snapshot(context.Background()); len(got) != 0 {
		t.Errorf("profiled %+v", got)
	}
}

func TestAHugeCountIsClamped(t *testing.T) {
	if clampCount(1<<40) != 1<<31 || clampCount(3) != 3 {
		t.Error("clampCount")
	}
}

func TestTheNewMethodsAreSafeOnANilProfiler(t *testing.T) {
	var p *ContinuousProfiler
	p.IngestOnCPU(oncpu.Drained{})
	if p.Source() != "" || p.Unjoined() != 0 || p.Stacks(context.Background(), StackSelection{}) != nil {
		t.Error("a nil profiler is not inert")
	}
}

func TestAFrameBudgetFallsBackToHexAddresses(t *testing.T) {
	r := &namingResolver{}
	f := &frameNames{ctx: context.Background(), resolver: r, memo: map[frameAddr]string{}, budget: 1}
	if got := f.name(1, 0xa); got != "fn_a" {
		t.Errorf("first = %q", got)
	}
	if got := f.name(1, 0xb); got != "0xb" {
		t.Errorf("past the budget = %q, want the hex address", got)
	}
	if f.name(1, 0xa) != "fn_a" || r.calls != 1 {
		t.Errorf("a remembered frame was resolved again (%d calls)", r.calls)
	}
}

func TestOnCPUStacksAgeOutWithTheWindow(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	p := onCPUProfiler()
	p.now = func() time.Time { return now }
	p.IngestOnCPU(oncpu.Drained{Samples: []oncpu.Sample{{CgroupID: 7, PID: 1, Stack: []uint64{0x100}, Count: 1}}})
	for range 2 {
		now = now.Add(defaultProfileWindow + time.Second)
		p.IngestOnCPU(oncpu.Drained{})
	}
	if got := p.Snapshot(context.Background()); len(got) != 0 {
		t.Errorf("a stack two windows old is still reported: %+v", got)
	}
}

func TestOnCPUIngestBoundsWorkloads(t *testing.T) {
	names := map[uint64]string{}
	var samples []oncpu.Sample
	for i := 0; i < maxProfiledWorkloads+1; i++ {
		names[uint64(i+1)] = fmt.Sprintf("w%d", i)
		samples = append(samples, oncpu.Sample{CgroupID: uint64(i + 1), PID: 1, Stack: []uint64{0x1}, Count: 2, CorrelationID: 5})
	}
	p := NewContinuousProfiler(nil, cgroupLookup(names))
	p.IngestOnCPU(oncpu.Drained{Samples: samples})
	if p.Dropped() != 2 {
		t.Errorf("dropped = %d, want the 2 samples of the workload past the cap", p.Dropped())
	}
	if len(p.pending) != maxProfiledWorkloads {
		t.Errorf("%d pending requests; a sample the profile refused must not be attributed", len(p.pending))
	}
}
