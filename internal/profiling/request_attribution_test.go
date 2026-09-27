package profiling

import (
	"context"
	"testing"

	"github.com/gma1k/podtrace/internal/ebpf/oncpu"
)

func sampleFor(correlation uint64, addr uint64, count uint64) oncpu.Sample {
	return oncpu.Sample{CgroupID: 7, PID: 1, CorrelationID: correlation, Stack: []uint64{addr, 0x999}, Count: count}
}

func done(correlation uint64, latencyMS uint64) oncpu.Completion {
	return oncpu.Completion{CgroupID: 7, CorrelationID: correlation, LatencyNS: latencyMS * 1e6}
}

func TestTheSlowestRequestsCPUIsJoinedByCorrelationID(t *testing.T) {
	p := onCPUProfiler()
	d := oncpu.Drained{}
	for i := uint64(1); i <= 99; i++ {
		d.Samples = append(d.Samples, sampleFor(i, 0x100, 1))
		d.Completions = append(d.Completions, done(i, 10))
	}
	d.Samples = append(d.Samples, sampleFor(1000, 0x500, 8), sampleFor(0, 0x700, 50))
	d.Completions = append(d.Completions, done(1000, 900))
	p.IngestOnCPU(d)

	slow := p.Snapshot(context.Background())[0].SlowRequests
	if slow == nil {
		t.Fatal("no slow-request profile")
	}
	if slow.Quantile != 0.99 || slow.ThresholdMilliseconds != 10 || slow.Requests != 100 {
		t.Errorf("slow = %+v; the p99 of 99 requests at 10ms and one at 900ms is 10ms", slow)
	}
	if slow.SampledRequests != 100 || slow.Samples != 107 {
		t.Errorf("slow = %+v", slow)
	}
	if slow.Frames[0].Frame != "fn_100" {
		t.Errorf("frames = %+v", slow.Frames)
	}
}

func TestOnlyRequestsAtOrAboveTheThresholdAreCounted(t *testing.T) {
	p := onCPUProfiler()
	d := oncpu.Drained{}
	for i := uint64(1); i <= 100; i++ {
		d.Samples = append(d.Samples, sampleFor(i, 0x100, 1))
		d.Completions = append(d.Completions, done(i, 10))
	}
	d.Samples = append(d.Samples, sampleFor(500, 0x500, 3), sampleFor(501, 0x600, 2))
	d.Completions = append(d.Completions, done(500, 800), done(501, 900))
	p.IngestOnCPU(d)

	slow := p.Snapshot(context.Background())[0].SlowRequests
	if slow.ThresholdMilliseconds != 800 || slow.SampledRequests != 2 || slow.Samples != 5 {
		t.Errorf("slow = %+v, want the two requests at 800ms and 900ms", slow)
	}
	stacks := p.Stacks(context.Background(), StackSelection{SlowRequests: true})
	if len(stacks) != 1 || len(stacks[0].Stacks) != 2 || stacks[0].Stacks[0].Frames[1] != "fn_500" {
		t.Errorf("slow stacks = %+v", stacks)
	}
}

func TestSamplesReadBeforeTheReplyWaitForIt(t *testing.T) {
	p := onCPUProfiler()
	p.IngestOnCPU(oncpu.Drained{Samples: []oncpu.Sample{sampleFor(42, 0x100, 4)}})
	if len(p.pending) != 1 {
		t.Fatalf("pending = %d", len(p.pending))
	}
	p.IngestOnCPU(oncpu.Drained{Completions: []oncpu.Completion{done(42, 50)}})

	slow := p.Snapshot(context.Background())[0].SlowRequests
	if slow == nil || slow.Samples != 4 || len(p.pending) != 0 {
		t.Errorf("slow = %+v, pending = %d; the reply must join the samples that waited for it", slow, len(p.pending))
	}
}

func TestSamplesReadAfterTheReplyAreStillCharged(t *testing.T) {
	p := onCPUProfiler()
	p.IngestOnCPU(oncpu.Drained{Completions: []oncpu.Completion{done(42, 50)}})
	p.IngestOnCPU(oncpu.Drained{Samples: []oncpu.Sample{sampleFor(42, 0x100, 4), sampleFor(42, 0x200, 1)}})

	slow := p.Snapshot(context.Background())[0].SlowRequests
	if slow == nil || slow.SampledRequests != 1 || slow.Samples != 5 || len(p.pending) != 0 {
		t.Errorf("slow = %+v, pending = %d", slow, len(p.pending))
	}
}

func TestARequestWhoseReplyNeverComesIsGivenUp(t *testing.T) {
	p := onCPUProfiler()
	p.IngestOnCPU(oncpu.Drained{Samples: []oncpu.Sample{sampleFor(42, 0x100, 4)}})
	for range pendingRequestDrains {
		p.IngestOnCPU(oncpu.Drained{})
	}
	if len(p.pending) != 0 || p.Unjoined() != 4 {
		t.Errorf("pending = %d, unjoined = %d", len(p.pending), p.Unjoined())
	}
	if got := p.Snapshot(context.Background())[0]; got.SlowRequests != nil || got.Samples != 4 {
		t.Errorf("profile = %+v; the samples still count for the workload", got)
	}
}

func TestTheRequestBoundsHold(t *testing.T) {
	p := onCPUProfiler()
	for i := 0; i < maxPendingRequests; i++ {
		p.pending[requestKey{cgroupID: 1, correlationID: uint64(i + 1)}] = &pendingRequest{}
	}
	p.IngestOnCPU(oncpu.Drained{Samples: []oncpu.Sample{sampleFor(1, 0x100, 3)}})
	if p.Unjoined() != 3 {
		t.Errorf("unjoined = %d, want the refused samples counted", p.Unjoined())
	}

	q := onCPUProfiler()
	q.IngestOnCPU(oncpu.Drained{})
	rw := q.requestWindowLocked(WorkloadKey{Namespace: "shop", Workload: "checkout"})
	for i := 0; i < maxSampledRequestsPerWorkload; i++ {
		rw.sampled[requestKey{correlationID: uint64(i + 1000000)}] = &sampledRequest{}
	}
	q.IngestOnCPU(oncpu.Drained{Samples: []oncpu.Sample{sampleFor(1, 0x100, 1)}, Completions: []oncpu.Completion{done(1, 5)}})
	q.IngestOnCPU(oncpu.Drained{Samples: []oncpu.Sample{sampleFor(1, 0x100, 1)}})
	if _, ok := rw.sampled[requestKey{cgroupID: 7, correlationID: 1}]; ok || len(q.pending) != 0 {
		t.Error("a workload kept more sampled requests than its cap")
	}

	many := map[stackKey]int{}
	for i := 0; i < maxStacksPerRequest+5; i++ {
		s, _ := newStackKey(1, []uint64{uint64(i + 1)})
		addBounded(many, s, 1)
	}
	if len(many) != maxStacksPerRequest {
		t.Errorf("one request kept %d stacks", len(many))
	}
}

func TestLatenciesPastTheCapAreAnEvenSampleOfTheWindow(t *testing.T) {
	p := onCPUProfiler()
	d := oncpu.Drained{}
	total := 3*maxLatenciesPerWorkload + 7
	for i := 1; i <= total; i++ {
		d.Completions = append(d.Completions, done(uint64(i), uint64(i)))
	}
	p.IngestOnCPU(d)

	rw := p.cur.requests[WorkloadKey{Namespace: "shop", Workload: "checkout"}]
	if rw.finished != total || len(rw.latencies) > maxLatenciesPerWorkload || len(rw.latencies) < maxLatenciesPerWorkload/2 {
		t.Fatalf("kept %d latencies of %d finished", len(rw.latencies), rw.finished)
	}
	for i, ns := range rw.latencies {
		want := uint64((i+1)*rw.stride) * 1e6
		if ns != want {
			t.Fatalf("latency %d = %d, want %d: the kept set must be every stride-th request", i, ns, want)
		}
	}
	if last := rw.latencies[len(rw.latencies)-1] / 1e6; int(last) < total-rw.stride {
		t.Errorf("the newest kept latency is from request %d of %d; the end of the window was lost", last, total)
	}
}

func TestDownsamplingKeepsTheSlowTailOfTheLatestRequests(t *testing.T) {
	p := onCPUProfiler()
	d := oncpu.Drained{}
	for i := 1; i <= 2*maxLatenciesPerWorkload; i++ {
		latency := uint64(10)
		if i > 2*maxLatenciesPerWorkload-maxLatenciesPerWorkload/20 {
			latency = 900
		}
		d.Completions = append(d.Completions, done(uint64(i), latency))
	}
	p.IngestOnCPU(d)
	if slow := p.Snapshot(context.Background()); len(slow) != 0 {
		t.Fatalf("a workload with no samples was profiled: %+v", slow)
	}
	if got := p.slowRequestsLocked()[WorkloadKey{Namespace: "shop", Workload: "checkout"}].threshold; got != 900e6 {
		t.Errorf("threshold = %dns; the 5%% of slow requests at the end of the window must still set the p99", got)
	}
}

func TestASlowRequestWithNoSamplesIsReportedAsWaiting(t *testing.T) {
	p := onCPUProfiler()
	p.IngestOnCPU(oncpu.Drained{
		Samples:     []oncpu.Sample{{CgroupID: 7, PID: 1, Stack: []uint64{0x100}, Count: 1}},
		Completions: []oncpu.Completion{done(1, 500)},
	})
	slow := p.Snapshot(context.Background())[0].SlowRequests
	if slow == nil || slow.Requests != 1 || slow.SampledRequests != 0 || slow.Samples != 0 || len(slow.Frames) != 0 {
		t.Errorf("slow = %+v", slow)
	}
}

func TestRequestsSplitAcrossWindowsAreMerged(t *testing.T) {
	p := onCPUProfiler()
	p.IngestOnCPU(oncpu.Drained{Samples: []oncpu.Sample{sampleFor(1, 0x100, 2)}, Completions: []oncpu.Completion{done(1, 40)}})
	p.rotatedAt = p.rotatedAt.Add(-2 * defaultProfileWindow)
	p.IngestOnCPU(oncpu.Drained{Samples: []oncpu.Sample{sampleFor(1, 0x100, 3)}})

	slow := p.Snapshot(context.Background())[0].SlowRequests
	if slow == nil || slow.SampledRequests != 1 || slow.Samples != 5 {
		t.Errorf("slow = %+v; one request charged in both windows is still one request", slow)
	}
}

func TestTheQuantileIsNearestRank(t *testing.T) {
	if got := quantile([]uint64{5, 1, 3}, 0.99); got != 5 {
		t.Errorf("p99 of three = %d", got)
	}
	if got := quantile([]uint64{7}, 0); got != 7 {
		t.Errorf("p0 of one = %d", got)
	}
}

func TestAWindowWithSampledRequestsButNoLatenciesIsSkipped(t *testing.T) {
	p := onCPUProfiler()
	p.cur.requests[WorkloadKey{Namespace: "shop", Workload: "checkout"}] = &requestWindow{
		sampled: map[requestKey]*sampledRequest{{correlationID: 1}: {stacks: map[stackKey]int{}}},
	}
	if got := p.slowRequestsLocked(); len(got) != 0 {
		t.Errorf("slow = %+v; no threshold can be found without a latency", got)
	}
}
