package status

import (
	"sort"
	"strings"

	"github.com/gma1k/podtrace/internal/profiling"
)

// WorkloadHotFrames is one workload's continuous profile, merged across every
// node it runs on.
type WorkloadHotFrames struct {
	Namespace string `json:"namespace"`
	Workload  string `json:"workload"`
	// Source is where the stacks came from, on-cpu or sched-switch; nodes
	// that disagree are listed together.
	Source          string     `json:"source"`
	Samples         int        `json:"samples"`
	SchedulerFrames int        `json:"schedulerFrames"`
	Nodes           int        `json:"nodes"`
	Frames          []HotFrame `json:"frames"`

	SlowRequests *SlowRequestFrames `json:"slowRequests,omitempty"`
}

// SlowRequestFrames is where a workload's slowest requests spent their CPU,
// merged across nodes. Each node finds its own threshold, so the merged one
// is a range.
type SlowRequestFrames struct {
	Quantile                 float64    `json:"quantile"`
	ThresholdMinMilliseconds float64    `json:"thresholdMinMilliseconds"`
	ThresholdMaxMilliseconds float64    `json:"thresholdMaxMilliseconds"`
	Requests                 int        `json:"requests"`
	SampledRequests          int        `json:"sampledRequests"`
	Samples                  int        `json:"samples"`
	Frames                   []HotFrame `json:"frames"`
}

// HotFrame is one function and the share of the workload's samples it was on.
type HotFrame struct {
	Frame   string  `json:"frame"`
	Count   int     `json:"count"`
	Percent float64 `json:"percent"`
}

// MergeProfiles combines the per-node profiles of one workload. It returns
// nil when no node has one.
func MergeProfiles(profiles []Profile, namespace, workload string, top int) *WorkloadHotFrames {
	out := &WorkloadHotFrames{Namespace: namespace, Workload: workload, Frames: []HotFrame{}}
	counts := map[string]int{}
	slowCounts := map[string]int{}
	sources := map[string]bool{}
	var slow *SlowRequestFrames
	for _, p := range profiles {
		for _, wp := range p.Profiles {
			if wp.Namespace != namespace || wp.Workload != workload {
				continue
			}
			out.Nodes++
			out.Samples += wp.Samples
			out.SchedulerFrames += wp.SchedulerFrames
			if wp.Source != "" {
				sources[string(wp.Source)] = true
			}
			for _, f := range wp.Frames {
				counts[f.Frame] += f.Count
			}
			if rp := wp.SlowRequests; rp != nil {
				slow = mergeSlowRequests(slow, rp)
				for _, f := range rp.Frames {
					slowCounts[f.Frame] += f.Count
				}
			}
		}
	}
	if out.Nodes == 0 {
		return nil
	}
	out.Source = joinSources(sources)
	out.Frames = rankFrames(counts, out.Samples, top)
	if slow != nil {
		slow.Frames = rankFrames(slowCounts, slow.Samples, top)
		out.SlowRequests = slow
	}
	return out
}

func mergeSlowRequests(into *SlowRequestFrames, rp *profiling.RequestProfile) *SlowRequestFrames {
	if into == nil {
		return &SlowRequestFrames{
			Quantile:                 rp.Quantile,
			ThresholdMinMilliseconds: rp.ThresholdMilliseconds,
			ThresholdMaxMilliseconds: rp.ThresholdMilliseconds,
			Requests:                 rp.Requests,
			SampledRequests:          rp.SampledRequests,
			Samples:                  rp.Samples,
		}
	}
	into.ThresholdMinMilliseconds = min(into.ThresholdMinMilliseconds, rp.ThresholdMilliseconds)
	into.ThresholdMaxMilliseconds = max(into.ThresholdMaxMilliseconds, rp.ThresholdMilliseconds)
	into.Requests += rp.Requests
	into.SampledRequests += rp.SampledRequests
	into.Samples += rp.Samples
	return into
}

func joinSources(sources map[string]bool) string {
	out := make([]string, 0, len(sources))
	for s := range sources {
		out = append(out, s)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// rankFrames orders frames busiest first, as a share of samples, keeping top.
func rankFrames(counts map[string]int, samples, top int) []HotFrame {
	out := make([]HotFrame, 0, len(counts))
	for frame, count := range counts {
		hf := HotFrame{Frame: frame, Count: count}
		if samples > 0 {
			hf.Percent = float64(count) / float64(samples) * 100
		}
		out = append(out, hf)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Frame < out[j].Frame
	})
	if top > 0 && len(out) > top {
		out = out[:top]
	}
	return out
}
