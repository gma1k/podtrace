package profiling

import (
	"context"
	"testing"

	"github.com/gma1k/podtrace/internal/ebpf/oncpu"
)

func fastRequests(from, count uint64) oncpu.Drained {
	d := oncpu.Drained{}
	for i := from; i < from+count; i++ {
		d.Samples = append(d.Samples, sampleFor(i, 0x100, 1))
		d.Completions = append(d.Completions, done(i, 1))
	}
	return d
}

func TestSlowRequestsLateInAFullWindowReplaceTheFastestKept(t *testing.T) {
	p := onCPUProfiler()
	p.IngestOnCPU(fastRequests(1, maxSampledRequestsPerWorkload))

	slow := oncpu.Drained{}
	for i := uint64(100_000); i < 100_100; i++ {
		slow.Samples = append(slow.Samples, sampleFor(i, 0x500, 2))
		slow.Completions = append(slow.Completions, done(i, 500))
	}
	p.IngestOnCPU(slow)

	profile := p.Snapshot(context.Background())[0].SlowRequests
	if profile == nil {
		t.Fatal("no slow-request profile")
	}
	if profile.ThresholdMilliseconds != 500 || profile.SampledRequests != 100 || profile.Samples != 200 {
		t.Fatalf("slow = %+v, want the 100 late 500ms requests kept", profile)
	}
	if profile.DisplacedSamples != 100 {
		t.Fatalf("displaced = %d, want the 100 samples of the fast requests they replaced", profile.DisplacedSamples)
	}
	if profile.Frames[0].Frame != "fn_500" {
		t.Fatalf("frames = %+v, want the slow requests' frame", profile.Frames)
	}
}

func slowWindow(t *testing.T) *ContinuousProfiler {
	t.Helper()
	p := onCPUProfiler()
	d := oncpu.Drained{}
	for i := uint64(1); i <= maxSampledRequestsPerWorkload; i++ {
		d.Samples = append(d.Samples, sampleFor(i, 0x500, 1))
		d.Completions = append(d.Completions, done(i, 500))
	}
	p.IngestOnCPU(d)
	return p
}

func displacedIn(p *ContinuousProfiler) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	total := 0
	for _, rw := range p.cur.requests {
		total += rw.displacedSamples
	}
	return total
}

func TestAFasterRequestThanEveryKeptOneIsCountedAsDisplaced(t *testing.T) {
	p := slowWindow(t)
	p.IngestOnCPU(oncpu.Drained{
		Samples:     []oncpu.Sample{sampleFor(50_000, 0x100, 3)},
		Completions: []oncpu.Completion{done(50_000, 1)},
	})
	if got := displacedIn(p); got != 3 {
		t.Fatalf("displaced = %d, want the 3 samples of the request not kept", got)
	}
}

func TestALateSampleOfARequestNotKeptIsCountedAsDisplaced(t *testing.T) {
	p := slowWindow(t)
	p.IngestOnCPU(oncpu.Drained{Completions: []oncpu.Completion{done(60_000, 1)}})
	p.IngestOnCPU(oncpu.Drained{Samples: []oncpu.Sample{sampleFor(60_000, 0x100, 4)}})
	if got := displacedIn(p); got != 4 {
		t.Fatalf("displaced = %d, want the late sample's 4", got)
	}
}

func TestSampledHeapPopsTheFastestRequest(t *testing.T) {
	var h sampledHeap
	for _, latency := range []uint64{30, 10, 20} {
		h.Push(&sampledRequest{latencyNS: latency})
	}
	h.Swap(0, 1)
	if h.Len() != 3 || !h.Less(0, 2) {
		t.Fatalf("heap = %+v", h)
	}
	if got := h.Pop().(*sampledRequest).latencyNS; got != 20 {
		t.Fatalf("Pop = %d, want the last element", got)
	}
}
