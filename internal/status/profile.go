package status

import "sort"

// WorkloadHotFrames is one workload's continuous profile, merged across every
// node it runs on.
type WorkloadHotFrames struct {
	Namespace       string     `json:"namespace"`
	Workload        string     `json:"workload"`
	Samples         int        `json:"samples"`
	SchedulerFrames int        `json:"schedulerFrames"`
	Nodes           int        `json:"nodes"`
	Frames          []HotFrame `json:"frames"`
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
	for _, p := range profiles {
		for _, wp := range p.Profiles {
			if wp.Namespace != namespace || wp.Workload != workload {
				continue
			}
			out.Nodes++
			out.Samples += wp.Samples
			out.SchedulerFrames += wp.SchedulerFrames
			for _, f := range wp.Frames {
				counts[f.Frame] += f.Count
			}
		}
	}
	if out.Nodes == 0 {
		return nil
	}
	for frame, count := range counts {
		hf := HotFrame{Frame: frame, Count: count}
		if out.Samples > 0 {
			hf.Percent = float64(count) / float64(out.Samples) * 100
		}
		out.Frames = append(out.Frames, hf)
	}
	sort.Slice(out.Frames, func(i, j int) bool {
		if out.Frames[i].Count != out.Frames[j].Count {
			return out.Frames[i].Count > out.Frames[j].Count
		}
		return out.Frames[i].Frame < out.Frames[j].Frame
	})
	if top > 0 && len(out.Frames) > top {
		out.Frames = out.Frames[:top]
	}
	return out
}
