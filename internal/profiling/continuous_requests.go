package profiling

import (
	"container/heap"
	"math"
	"sort"

	"github.com/gma1k/podtrace/internal/safeconv"
)

// Per-request attribution. The receive hook that sees a request arrive marks
// the thread reading it as serving that request, and every on-CPU sample on
// that thread until the reply is written carries the request's correlation
// id: the same Event.CorrelationID its request and response events carry. The
// reply records how long the request took under the same id. The profiler
// joins the two here, so it can answer where the slowest requests spent their
// CPU without guessing from time windows.
//
// The join is exact for runtimes that serve a request on one thread. In Go a
// handler's goroutine can move between threads, so samples taken after it
// moves are not charged to it. In an event loop one thread interleaves many
// requests, so a sample is charged to whichever request that thread last
// read.
const (
	slowRequestQuantile = 0.99

	maxLatenciesPerWorkload = 8192

	maxSampledRequestsPerWorkload = 4096

	maxStacksPerRequest = 256

	maxPendingRequests = 8192

	pendingRequestDrains = 12
)

// RequestProfile is where one workload's slowest requests spent their CPU.
// DisplacedSamples are CPU samples of requests a window did not keep because
// it already held maxSampledRequestsPerWorkload slower ones.
type RequestProfile struct {
	Quantile              float64      `json:"quantile"`
	ThresholdMilliseconds float64      `json:"thresholdMilliseconds"`
	Requests              int          `json:"requests"`
	SampledRequests       int          `json:"sampledRequests"`
	Samples               int          `json:"samples"`
	DisplacedSamples      int          `json:"displacedSamples,omitempty"`
	Frames                []FrameCount `json:"frames"`
}

// requestKey is a request as the kernel names it: the correlation id is the
// request's start timestamp, so it is paired with the cgroup to keep two
// processes that happen to share one apart.
type requestKey struct {
	cgroupID      uint64
	correlationID uint64
}

type pendingRequest struct {
	workload WorkloadKey
	stacks   map[stackKey]int
	drains   int
}

type completion struct {
	workload  WorkloadKey
	latencyNS uint64
}

type sampledRequest struct {
	key       requestKey
	latencyNS uint64
	stacks    map[stackKey]int
}

// requestWindow is one workload's finished requests over one window.
type requestWindow struct {
	latencies []uint64
	// stride is how many finished requests each kept latency stands for.
	stride   int
	finished int
	sampled  map[requestKey]*sampledRequest
	// slowest orders sampled by latency, fastest first, so that once the
	// window keeps as many requests as it may, a slower one replaces the
	// fastest kept instead of being turned away.
	slowest sampledHeap
	// displacedSamples counts the CPU samples of requests the window let go
	// of, or never kept, because it already held that many slower ones.
	displacedSamples int
}

func (p *ContinuousProfiler) requestWindowLocked(key WorkloadKey) *requestWindow {
	rw, ok := p.cur.requests[key]
	if !ok {
		rw = &requestWindow{sampled: map[requestKey]*sampledRequest{}}
		p.cur.requests[key] = rw
	}
	return rw
}

// sampledHeap is a min-heap of sampled requests by latency.
type sampledHeap []*sampledRequest

func (h sampledHeap) Len() int           { return len(h) }
func (h sampledHeap) Less(i, j int) bool { return h[i].latencyNS < h[j].latencyNS }
func (h sampledHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *sampledHeap) Push(x any)        { *h = append(*h, x.(*sampledRequest)) }

func (h *sampledHeap) Pop() any {
	old := *h
	n := len(old)
	sr := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	return sr
}

func addBounded(into map[stackKey]int, stack stackKey, n int) {
	if _, seen := into[stack]; !seen && len(into) >= maxStacksPerRequest {
		return
	}
	into[stack] += n
}

// attributeLocked charges samples to a request. A request whose reply came in
// the previous drain is charged directly: the counts map is read before the
// replies, so a sample taken just before a reply can land one drain after it.
func (p *ContinuousProfiler) attributeLocked(key WorkloadKey, rk requestKey, stack stackKey, n int) {
	if done, ok := p.finished[rk]; ok {
		if sr := p.sampledLocked(done.workload, rk, done.latencyNS); sr != nil {
			addBounded(sr.stacks, stack, n)
		} else {
			p.requestWindowLocked(done.workload).displacedSamples += n
		}
		return
	}
	pr, ok := p.pending[rk]
	if !ok {
		if len(p.pending) >= maxPendingRequests {
			p.unjoined += safeconv.IntToUint64(n)
			return
		}
		pr = &pendingRequest{workload: key, stacks: map[stackKey]int{}}
		p.pending[rk] = pr
	}
	addBounded(pr.stacks, stack, n)
}

// sampledLocked returns the current window's record of a finished request,
// creating it. A window keeps the maxSampledRequestsPerWorkload slowest
// requests: when it is full, a request slower than the fastest kept replaces
// it, and any other is not kept and nil is returned. Only the slowest
// requests reach a slow-request profile, so keeping the first ones to finish
// lost every slow request after the first seconds of a busy window.
func (p *ContinuousProfiler) sampledLocked(key WorkloadKey, rk requestKey, latencyNS uint64) *sampledRequest {
	rw := p.requestWindowLocked(key)
	sr, ok := rw.sampled[rk]
	if ok {
		return sr
	}
	if len(rw.sampled) >= maxSampledRequestsPerWorkload {
		if len(rw.slowest) == 0 || latencyNS <= rw.slowest[0].latencyNS {
			return nil
		}
		fastest := heap.Pop(&rw.slowest).(*sampledRequest)
		delete(rw.sampled, fastest.key)
		for _, c := range fastest.stacks {
			rw.displacedSamples += c
		}
	}
	sr = &sampledRequest{key: rk, latencyNS: latencyNS, stacks: map[stackKey]int{}}
	rw.sampled[rk] = sr
	heap.Push(&rw.slowest, sr)
	return sr
}

// keepLatency counts a finished request and keeps its latency if it falls on
// the current stride. When the kept set is full, every other latency is
// dropped and the stride doubles, which keeps the set an even sample of the
// window in the order requests finished.
func (rw *requestWindow) keepLatency(latencyNS uint64) {
	rw.finished++
	if rw.stride == 0 {
		rw.stride = 1
	}
	if rw.finished%rw.stride != 0 {
		return
	}
	if len(rw.latencies) >= maxLatenciesPerWorkload {
		kept := rw.latencies[:0]
		for i := 1; i < len(rw.latencies); i += 2 {
			kept = append(kept, rw.latencies[i])
		}
		rw.latencies = kept
		rw.stride *= 2
		if rw.finished%rw.stride != 0 {
			return
		}
	}
	rw.latencies = append(rw.latencies, latencyNS)
}

// completeLocked records a finished request's latency and joins any samples
// already waiting for it.
func (p *ContinuousProfiler) completeLocked(key WorkloadKey, rk requestKey, latencyNS uint64) {
	rw := p.requestWindowLocked(key)
	rw.keepLatency(latencyNS)
	p.finishing[rk] = completion{workload: key, latencyNS: latencyNS}

	pr, ok := p.pending[rk]
	if !ok {
		return
	}
	delete(p.pending, rk)
	sr := p.sampledLocked(key, rk, latencyNS)
	if sr == nil {
		for _, c := range pr.stacks {
			rw.displacedSamples += c
		}
		return
	}
	for s, c := range pr.stacks {
		addBounded(sr.stacks, s, c)
	}
}

// agePendingLocked gives up on requests whose reply never came, and keeps
// this drain's replies for the next one's late samples.
func (p *ContinuousProfiler) agePendingLocked() {
	for rk, pr := range p.pending {
		pr.drains++
		if pr.drains < pendingRequestDrains {
			continue
		}
		for _, c := range pr.stacks {
			p.unjoined += safeconv.IntToUint64(c)
		}
		delete(p.pending, rk)
	}
	p.finished = p.finishing
	p.finishing = map[requestKey]completion{}
}

// Unjoined reports samples charged to a request whose reply was never seen.
func (p *ContinuousProfiler) Unjoined() uint64 {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.unjoined
}

// slowRequests is one workload's slow requests, before symbolising.
type slowRequests struct {
	threshold uint64
	finished  int
	sampled   int
	samples   int
	displaced int
	stacks    map[stackKey]int
}

func (s *slowRequests) profile(names *frameNames) *RequestProfile {
	frames, _ := selfFrames(s.stacks, names, false)
	return &RequestProfile{
		Quantile:              slowRequestQuantile,
		ThresholdMilliseconds: float64(s.threshold) / 1e6,
		Requests:              s.finished,
		SampledRequests:       s.sampled,
		Samples:               s.samples,
		DisplacedSamples:      s.displaced,
		Frames:                frames,
	}
}

// slowRequestsLocked finds each workload's latency threshold over both
// windows and gathers the stacks of the requests at or above it.
func (p *ContinuousProfiler) slowRequestsLocked() map[WorkloadKey]*slowRequests {
	type merged struct {
		latencies []uint64
		finished  int
		displaced int
		sampled   map[requestKey]*sampledRequest
	}
	all := map[WorkloadKey]*merged{}
	for _, half := range []*profileWindow{p.prev, p.cur} {
		for key, rw := range half.requests {
			m, ok := all[key]
			if !ok {
				m = &merged{sampled: map[requestKey]*sampledRequest{}}
				all[key] = m
			}
			m.latencies = append(m.latencies, rw.latencies...)
			m.finished += rw.finished
			m.displaced += rw.displacedSamples
			for rk, sr := range rw.sampled {
				into, ok := m.sampled[rk]
				if !ok {
					into = &sampledRequest{latencyNS: sr.latencyNS, stacks: map[stackKey]int{}}
					m.sampled[rk] = into
				}
				for s, c := range sr.stacks {
					into.stacks[s] += c
				}
			}
		}
	}

	out := map[WorkloadKey]*slowRequests{}
	for key, m := range all {
		if len(m.latencies) == 0 {
			continue
		}
		s := &slowRequests{
			threshold: quantile(m.latencies, slowRequestQuantile),
			finished:  m.finished,
			displaced: m.displaced,
			stacks:    map[stackKey]int{},
		}
		for _, sr := range m.sampled {
			if sr.latencyNS < s.threshold || len(sr.stacks) == 0 {
				continue
			}
			s.sampled++
			for st, c := range sr.stacks {
				s.stacks[st] += c
				s.samples += c
			}
		}
		out[key] = s
	}
	return out
}

// quantile is the nearest-rank quantile of a non-empty set of latencies.
func quantile(latencies []uint64, q float64) uint64 {
	sorted := append([]uint64(nil), latencies...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	rank := int(math.Ceil(q*float64(len(sorted)))) - 1
	if rank < 0 {
		rank = 0
	}
	return sorted[rank]
}
