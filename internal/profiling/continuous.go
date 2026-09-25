package profiling

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/gma1k/podtrace/internal/events"
)

// Continuous profiling here is not the pprof fetch Handler performs. Handler
// needs a pod IP, a pprof port and a Go runtime willing to serve one, which is
// why it only ever ran inside a session an operator asked for. This aggregates
// the user stacks the kernel already captures on every sched_switch, so it
// works for any language, needs nothing exposed by the workload, and costs one
// map increment per sample.
const (
	defaultProfileWindow = 5 * time.Minute

	maxProfiledWorkloads = 200

	maxFramesPerWorkload = 4096
)

// WorkloadKey identifies the workload a profile belongs to.
type WorkloadKey struct {
	Namespace string
	Workload  string
}

// WorkloadProfile is one workload's hot functions over the current window.
type WorkloadProfile struct {
	Namespace string       `json:"namespace"`
	Workload  string       `json:"workload"`
	Samples   int          `json:"samples"`
	Frames    []FrameCount `json:"frames"`

	SchedulerFrames int `json:"schedulerFrames"`
}

// ContinuousProfiler is a tracer.Exporter that keeps a rolling CPU profile per
// workload from the stacks already on the event stream.
type ContinuousProfiler struct {
	mu sync.Mutex

	cur  map[WorkloadKey]map[frameAddr]int
	prev map[WorkloadKey]map[frameAddr]int

	rotatedAt time.Time
	window    time.Duration

	newResolver func() FrameResolver
	lookup      MetadataLookup
	now         func() time.Time

	symbolizeMu sync.Mutex

	dropped uint64
}

// MetadataLookup resolves a cgroup id to the workload that owns it.
type MetadataLookup func(cgroupID uint64) (events.K8sMetadata, bool)

// NewContinuousProfiler builds a profiler.
func NewContinuousProfiler(newResolver func() FrameResolver, lookup MetadataLookup) *ContinuousProfiler {
	return &ContinuousProfiler{
		cur:         map[WorkloadKey]map[frameAddr]int{},
		prev:        map[WorkloadKey]map[frameAddr]int{},
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
	if p.lookup == nil {
		return WorkloadKey{}, false
	}
	meta, ok := p.lookup(e.CgroupID)
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

// Export folds one batch of events into the current window.
func (p *ContinuousProfiler) Export(_ context.Context, batch []*events.Event) error {
	if p == nil {
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.rotateLocked()

	for _, e := range batch {
		if e == nil || e.Type != events.EventSchedSwitch || len(e.Stack) == 0 {
			continue
		}
		key, ok := p.workloadOf(e)
		if !ok {
			continue
		}

		frames, seen := p.cur[key]
		if !seen {
			if len(p.cur) >= maxProfiledWorkloads {
				p.dropped++
				continue
			}
			frames = map[frameAddr]int{}
			p.cur[key] = frames
		}

		for i, addr := range e.Stack {
			if i >= maxCorrelatedStackDepth {
				break
			}
			if addr == 0 {
				continue
			}
			f := frameAddr{pid: e.PID, addr: addr}
			if _, seen := frames[f]; !seen && len(frames) >= maxFramesPerWorkload {
				p.dropped++
				continue
			}
			frames[f]++
		}
	}
	return nil
}

// rotateLocked ages the window on, discarding what is now two windows old.
func (p *ContinuousProfiler) rotateLocked() {
	now := p.now()
	if now.Sub(p.rotatedAt) < p.window {
		return
	}
	p.prev = p.cur
	p.cur = map[WorkloadKey]map[frameAddr]int{}
	p.rotatedAt = now
}

// Snapshot symbolises and returns the hot functions of every tracked workload.
func (p *ContinuousProfiler) Snapshot(ctx context.Context) []WorkloadProfile {
	if p == nil {
		return nil
	}

	p.mu.Lock()
	merged := map[WorkloadKey]map[frameAddr]int{}
	for _, half := range []map[WorkloadKey]map[frameAddr]int{p.prev, p.cur} {
		for key, frames := range half {
			into, ok := merged[key]
			if !ok {
				into = make(map[frameAddr]int, len(frames))
				merged[key] = into
			}
			for f, c := range frames {
				into[f] += c
			}
		}
	}
	p.mu.Unlock()

	p.symbolizeMu.Lock()
	defer p.symbolizeMu.Unlock()
	var resolver FrameResolver
	if p.newResolver != nil {
		resolver = p.newResolver()
	}

	out := make([]WorkloadProfile, 0, len(merged))
	for key, frames := range merged {
		samples := 0
		for _, c := range frames {
			samples += c
		}
		if samples == 0 {
			continue
		}
		hot, hidden := symbolizeHotFramesHidingScheduler(ctx, frames, resolver)
		out = append(out, WorkloadProfile{
			Namespace:       key.Namespace,
			Workload:        key.Workload,
			Samples:         samples,
			Frames:          hot,
			SchedulerFrames: hidden,
		})
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
