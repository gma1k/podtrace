package profiling

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/oncpu"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/safeconv"
)

// Continuous profiling here is not the pprof fetch Handler performs. Handler
// needs a pod IP, a pprof port and a Go runtime willing to serve one, which is
// why it only ever ran inside a session an operator asked for. This keeps a
// rolling per-workload set of whole user stacks, so it works for any language
// and needs nothing exposed by the workload.
//
// The stacks come from the fixed-rate on-CPU sampler when the backend can run
// it. Until then, or on a backend that cannot, they come from the stacks every
// sched_switch already carries. Those show where a task went off the CPU, not
// where it was running, so a hot loop that never blocks is barely visible in
// them; the profile says which source it was built from.
const (
	defaultProfileWindow = 5 * time.Minute

	maxProfiledWorkloads = 200

	maxStacksPerWorkload = 4096

	maxFrameLookups = 16384
)

// ProfileSource names where a profile's stacks came from.
type ProfileSource string

const (
	SourceOnCPU       ProfileSource = "on-cpu"
	SourceSchedSwitch ProfileSource = "sched-switch"
)

// WorkloadKey identifies the workload a profile belongs to.
type WorkloadKey struct {
	Namespace string
	Workload  string
}

// WorkloadProfile is one workload's hot functions over the current window.
type WorkloadProfile struct {
	Namespace string        `json:"namespace"`
	Workload  string        `json:"workload"`
	Source    ProfileSource `json:"source"`
	Samples   int           `json:"samples"`
	Frames    []FrameCount  `json:"frames"`

	SchedulerFrames int `json:"schedulerFrames"`

	SlowRequests *RequestProfile `json:"slowRequests,omitempty"`
}

// stackKey is one whole user stack in one process, innermost frame first.
// The addresses are packed into a string so the stack can key a map.
type stackKey struct {
	pid    uint32
	frames string
}

func newStackKey(pid uint32, addrs []uint64) (stackKey, bool) {
	buf := make([]byte, 0, 8*len(addrs))
	n := 0
	for _, addr := range addrs {
		if n >= config.MaxStackDepth {
			break
		}
		if addr == 0 {
			continue
		}
		buf = binary.LittleEndian.AppendUint64(buf, addr)
		n++
	}
	if n == 0 {
		return stackKey{}, false
	}
	return stackKey{pid: pid, frames: string(buf)}, true
}

func (k stackKey) addrs() []uint64 {
	out := make([]uint64, len(k.frames)/8)
	for i := range out {
		out[i] = binary.LittleEndian.Uint64([]byte(k.frames[8*i : 8*i+8]))
	}
	return out
}

// workloadStacks is one workload's stacks in one window.
type workloadStacks struct {
	stacks  map[stackKey]int
	samples int
}

// profileWindow is everything captured over one window.
type profileWindow struct {
	workloads map[WorkloadKey]*workloadStacks
	requests  map[WorkloadKey]*requestWindow
}

func newProfileWindow() *profileWindow {
	return &profileWindow{
		workloads: map[WorkloadKey]*workloadStacks{},
		requests:  map[WorkloadKey]*requestWindow{},
	}
}

// ContinuousProfiler is a tracer.Exporter that keeps a rolling CPU profile per
// workload.
type ContinuousProfiler struct {
	mu sync.Mutex

	cur  *profileWindow
	prev *profileWindow

	source ProfileSource

	pending   map[requestKey]*pendingRequest
	finishing map[requestKey]completion
	finished  map[requestKey]completion

	rotatedAt time.Time
	window    time.Duration

	newResolver func() FrameResolver
	lookup      MetadataLookup
	now         func() time.Time

	symbolizeMu sync.Mutex

	dropped  uint64
	unjoined uint64
}

// MetadataLookup resolves a cgroup id to the workload that owns it.
type MetadataLookup func(cgroupID uint64) (events.K8sMetadata, bool)

// NewContinuousProfiler builds a profiler.
func NewContinuousProfiler(newResolver func() FrameResolver, lookup MetadataLookup) *ContinuousProfiler {
	return &ContinuousProfiler{
		cur:         newProfileWindow(),
		prev:        newProfileWindow(),
		source:      SourceSchedSwitch,
		pending:     map[requestKey]*pendingRequest{},
		finishing:   map[requestKey]completion{},
		finished:    map[requestKey]completion{},
		window:      defaultProfileWindow,
		newResolver: newResolver,
		lookup:      lookup,
		now:         time.Now,
		rotatedAt:   time.Now(),
	}
}

// workloadOf resolves the workload an event belongs to, preferring metadata
// already on the event and falling back to the cgroup lookup.
func (p *ContinuousProfiler) workloadOf(e *events.Event) (WorkloadKey, bool) {
	if e.K8s != nil && !e.K8s.IsZero() {
		return keyOf(*e.K8s)
	}
	return p.workloadOfCgroup(e.CgroupID)
}

func (p *ContinuousProfiler) workloadOfCgroup(cgroupID uint64) (WorkloadKey, bool) {
	if p.lookup == nil {
		return WorkloadKey{}, false
	}
	meta, ok := p.lookup(cgroupID)
	if !ok {
		return WorkloadKey{}, false
	}
	return keyOf(meta)
}

func keyOf(meta events.K8sMetadata) (WorkloadKey, bool) {
	if meta.Namespace == "" || meta.WorkloadName == "" {
		return WorkloadKey{}, false
	}
	return WorkloadKey{Namespace: meta.Namespace, Workload: meta.WorkloadName}, true
}

func (p *ContinuousProfiler) Name() string { return "continuous-profiler" }

func (p *ContinuousProfiler) Close(context.Context) error { return nil }

// Export folds the sched_switch stacks in one batch of events into the current
// window. Once the on-CPU sampler feeds the profiler they are ignored: the two
// measure different things and a profile mixing them would mean neither.
func (p *ContinuousProfiler) Export(_ context.Context, batch []*events.Event) error {
	if p == nil {
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.source != SourceSchedSwitch {
		return nil
	}
	p.rotateLocked()

	for _, e := range batch {
		if e == nil || e.Type != events.EventSchedSwitch || len(e.Stack) == 0 {
			continue
		}
		key, ok := p.workloadOf(e)
		if !ok {
			continue
		}
		stack, ok := newStackKey(e.PID, e.Stack)
		if !ok {
			continue
		}
		p.addStackLocked(key, stack, 1)
	}
	return nil
}

// addStackLocked counts n samples of one stack against a workload, reporting
// whether the workload is tracked.
func (p *ContinuousProfiler) addStackLocked(key WorkloadKey, stack stackKey, n int) bool {
	ws, seen := p.cur.workloads[key]
	if !seen {
		if len(p.cur.workloads) >= maxProfiledWorkloads {
			p.dropped += safeconv.IntToUint64(n)
			return false
		}
		ws = &workloadStacks{stacks: map[stackKey]int{}}
		p.cur.workloads[key] = ws
	}
	ws.samples += n
	if _, seen := ws.stacks[stack]; !seen && len(ws.stacks) >= maxStacksPerWorkload {
		p.dropped += safeconv.IntToUint64(n)
		return true
	}
	ws.stacks[stack] += n
	return true
}

// rotateLocked ages the window on, discarding what is now two windows old.
func (p *ContinuousProfiler) rotateLocked() {
	now := p.now()
	if now.Sub(p.rotatedAt) < p.window {
		return
	}
	p.prev = p.cur
	p.cur = newProfileWindow()
	p.rotatedAt = now
}

// IngestOnCPU folds one drain of the on-CPU sampler into the current window.
// The first call switches the profiler's source and discards the sched_switch
// stacks gathered before the sampler started.
func (p *ContinuousProfiler) IngestOnCPU(d oncpu.Drained) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.source != SourceOnCPU {
		p.source = SourceOnCPU
		p.cur = newProfileWindow()
		p.prev = newProfileWindow()
		p.rotatedAt = p.now()
	}
	p.rotateLocked()

	for _, s := range d.Samples {
		key, ok := p.workloadOfCgroup(s.CgroupID)
		if !ok {
			continue
		}
		stack, ok := newStackKey(s.PID, s.Stack)
		if !ok {
			continue
		}
		n := clampCount(s.Count)
		if !p.addStackLocked(key, stack, n) || s.CorrelationID == 0 {
			continue
		}
		p.attributeLocked(key, requestKey{cgroupID: s.CgroupID, correlationID: s.CorrelationID}, stack, n)
	}
	for _, c := range d.Completions {
		key, ok := p.workloadOfCgroup(c.CgroupID)
		if !ok {
			continue
		}
		p.completeLocked(key, requestKey{cgroupID: c.CgroupID, correlationID: c.CorrelationID}, c.LatencyNS)
	}
	p.agePendingLocked()
}

func clampCount(c uint64) int {
	const maxCount = 1 << 31
	if c > maxCount {
		return maxCount
	}
	return int(c)
}

// Source reports where the profiler's stacks currently come from.
func (p *ContinuousProfiler) Source() ProfileSource {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.source
}

// mergedStacks is one workload's stacks over both windows.
type mergedStacks struct {
	stacks  map[stackKey]int
	samples int
}

// mergeLocked folds both windows into one set of stacks per workload.
func (p *ContinuousProfiler) mergeLocked() map[WorkloadKey]*mergedStacks {
	merged := map[WorkloadKey]*mergedStacks{}
	for _, half := range []*profileWindow{p.prev, p.cur} {
		for key, ws := range half.workloads {
			into, ok := merged[key]
			if !ok {
				into = &mergedStacks{stacks: make(map[stackKey]int, len(ws.stacks))}
				merged[key] = into
			}
			into.samples += ws.samples
			for s, c := range ws.stacks {
				into.stacks[s] += c
			}
		}
	}
	return merged
}

// Snapshot symbolises and returns the hot functions of every tracked workload.
func (p *ContinuousProfiler) Snapshot(ctx context.Context) []WorkloadProfile {
	if p == nil {
		return nil
	}

	p.mu.Lock()
	source := p.source
	merged := p.mergeLocked()
	slow := p.slowRequestsLocked()
	p.mu.Unlock()

	p.symbolizeMu.Lock()
	defer p.symbolizeMu.Unlock()
	names := p.newFrameNames(ctx)

	skipScheduler := source == SourceSchedSwitch
	out := make([]WorkloadProfile, 0, len(merged))
	for key, m := range merged {
		hot, hidden := selfFrames(m.stacks, names, skipScheduler)
		wp := WorkloadProfile{
			Namespace:       key.Namespace,
			Workload:        key.Workload,
			Source:          source,
			Samples:         m.samples,
			Frames:          hot,
			SchedulerFrames: hidden,
		}
		if s, ok := slow[key]; ok {
			wp.SlowRequests = s.profile(names)
		}
		out = append(out, wp)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Samples != out[j].Samples {
			return out[i].Samples > out[j].Samples
		}
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Workload < out[j].Workload
	})
	return out
}

// Dropped reports samples refused because a bound was reached, so a node that
// is silently profiling only part of its workloads can say so.
func (p *ContinuousProfiler) Dropped() uint64 {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dropped
}

// frameNames symbolises addresses for one snapshot, remembering each answer
// and giving up on new addresses once the lookup budget is spent.
type frameNames struct {
	ctx      context.Context
	resolver FrameResolver
	memo     map[frameAddr]string
	budget   int
}

func (p *ContinuousProfiler) newFrameNames(ctx context.Context) *frameNames {
	f := &frameNames{ctx: ctx, memo: map[frameAddr]string{}, budget: maxFrameLookups}
	if p.newResolver != nil {
		f.resolver = p.newResolver()
	}
	return f
}

func (f *frameNames) name(pid uint32, addr uint64) string {
	key := frameAddr{pid: pid, addr: addr}
	if n, ok := f.memo[key]; ok {
		return n
	}
	var n string
	if f.resolver != nil && f.budget > 0 {
		f.budget--
		n = f.resolver.Resolve(f.ctx, pid, addr)
	}
	if n == "" {
		n = fmt.Sprintf("0x%x", addr)
	}
	f.memo[key] = n
	return n
}

// rankedStacks orders stacks busiest first, with a stable order for ties.
func rankedStacks(stacks map[stackKey]int) []stackKey {
	out := make([]stackKey, 0, len(stacks))
	for s := range stacks {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if stacks[out[i]] != stacks[out[j]] {
			return stacks[out[i]] > stacks[out[j]]
		}
		if out[i].pid != out[j].pid {
			return out[i].pid < out[j].pid
		}
		return out[i].frames < out[j].frames
	})
	return out
}

// selfFrames charges each sample to the function it was executing and returns
// the hottest.
func selfFrames(stacks map[stackKey]int, names *frameNames, skipScheduler bool) ([]FrameCount, int) {
	counts := map[string]int{}
	hidden := 0
	for _, s := range rankedStacks(stacks) {
		c := stacks[s]
		chosen := ""
		skipped := false
		for _, addr := range s.addrs() {
			n := names.name(s.pid, addr)
			if skipScheduler && isSchedulerFrame(n) {
				skipped = true
				continue
			}
			chosen = n
			break
		}
		if skipped {
			hidden += c
		}
		if chosen != "" {
			counts[chosen] += c
		}
	}

	out := make([]FrameCount, 0, len(counts))
	for n, c := range counts {
		out = append(out, FrameCount{Frame: n, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Frame < out[j].Frame
	})
	if len(out) > maxReportedFrames {
		out = out[:maxReportedFrames]
	}
	return out, hidden
}
