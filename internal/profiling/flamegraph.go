package profiling

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/google/pprof/profile"

	"github.com/gma1k/podtrace/internal/ebpf/oncpu"
	"github.com/gma1k/podtrace/internal/sanitize"
)

// StackSelection picks which stacks a flame graph is drawn from.
type StackSelection struct {
	// Namespace and Workload, when set, keep only that workload.
	Namespace string
	Workload  string
	// SlowRequests keeps only the samples charged to requests at or above
	// the workload's slow-request threshold.
	SlowRequests bool
}

func (s StackSelection) keeps(key WorkloadKey) bool {
	return (s.Namespace == "" || s.Namespace == key.Namespace) &&
		(s.Workload == "" || s.Workload == key.Workload)
}

// NamedStack is one symbolised stack, outermost frame first, the order both
// the folded format and a reader of a flame graph expect.
type NamedStack struct {
	Frames []string
	Count  int
}

// WorkloadStacks is one workload's symbolised stacks.
type WorkloadStacks struct {
	Namespace string
	Workload  string
	Stacks    []NamedStack
}

// Stacks symbolises the whole stacks a flame graph needs.
func (p *ContinuousProfiler) Stacks(ctx context.Context, sel StackSelection) []WorkloadStacks {
	if p == nil {
		return nil
	}

	p.mu.Lock()
	picked := map[WorkloadKey]map[stackKey]int{}
	if sel.SlowRequests {
		for key, s := range p.slowRequestsLocked() {
			if sel.keeps(key) && len(s.stacks) > 0 {
				picked[key] = s.stacks
			}
		}
	} else {
		for key, m := range p.mergeLocked() {
			if sel.keeps(key) && len(m.stacks) > 0 {
				picked[key] = m.stacks
			}
		}
	}
	p.mu.Unlock()

	p.symbolizeMu.Lock()
	defer p.symbolizeMu.Unlock()
	names := p.newFrameNames(ctx)

	out := make([]WorkloadStacks, 0, len(picked))
	for key, stacks := range picked {
		ws := WorkloadStacks{Namespace: key.Namespace, Workload: key.Workload}
		for _, s := range rankedStacks(stacks) {
			addrs := s.addrs()
			frames := make([]string, len(addrs))
			for i, addr := range addrs {
				frames[len(addrs)-1-i] = names.name(s.pid, addr)
			}
			ws.Stacks = append(ws.Stacks, NamedStack{Frames: frames, Count: stacks[s]})
		}
		out = append(out, ws)
	}
	sortWorkloadStacks(out)
	return out
}

func sortWorkloadStacks(out []WorkloadStacks) {
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Workload < out[j].Workload
	})
}

// foldedFrame makes a frame name safe inside one folded line: the format
// separates frames with ';' and ends a line with a space and the count, and a
// name comes from a binary the workload's owner controls.
func foldedFrame(name string) string {
	return strings.ReplaceAll(sanitize.Terminal(name), ";", ":")
}

// WriteFolded writes stacks in the folded format flamegraph.pl, speedscope
// and Grafana read: one line per stack, frames outermost first separated by
// ';', then a space and the sample count. The first frame is the workload, so
// the stacks of several workloads, or of several nodes, can be summed line by
// line into one graph.
func WriteFolded(w io.Writer, profiles []WorkloadStacks) error {
	bw := bufio.NewWriter(w)
	for _, ws := range profiles {
		root := foldedFrame(ws.Namespace + "/" + ws.Workload)
		for _, s := range ws.Stacks {
			var line strings.Builder
			line.WriteString(root)
			for _, f := range s.Frames {
				line.WriteByte(';')
				line.WriteString(foldedFrame(f))
			}
			fmt.Fprintf(&line, " %d\n", s.Count)
			if _, err := bw.WriteString(line.String()); err != nil {
				return err
			}
		}
	}
	return bw.Flush()
}

// maxFoldedLineBytes bounds one line ParseFolded accepts.
const maxFoldedLineBytes = 1 << 20

// ParseFolded reads what WriteFolded wrote, summing repeated stacks, so the
// folded output of several agents merges into one set of stacks.
func ParseFolded(r io.Reader) ([]WorkloadStacks, error) {
	type wl struct{ ns, name string }
	counts := map[wl]map[string]int{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxFoldedLineBytes)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		i := strings.LastIndexByte(text, ' ')
		if i < 0 {
			return nil, fmt.Errorf("folded line %d: no sample count", line)
		}
		n, err := strconv.Atoi(text[i+1:])
		if err != nil || n < 0 {
			return nil, fmt.Errorf("folded line %d: bad sample count %q", line, text[i+1:])
		}
		root, rest, _ := strings.Cut(text[:i], ";")
		ns, name, ok := strings.Cut(root, "/")
		if !ok || rest == "" {
			return nil, fmt.Errorf("folded line %d: expected namespace/workload;frames", line)
		}
		k := wl{ns, name}
		if counts[k] == nil {
			counts[k] = map[string]int{}
		}
		counts[k][rest] += n
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	out := make([]WorkloadStacks, 0, len(counts))
	for k, stacks := range counts {
		ws := WorkloadStacks{Namespace: k.ns, Workload: k.name}
		for frames, n := range stacks {
			ws.Stacks = append(ws.Stacks, NamedStack{Frames: strings.Split(frames, ";"), Count: n})
		}
		sort.Slice(ws.Stacks, func(i, j int) bool {
			if ws.Stacks[i].Count != ws.Stacks[j].Count {
				return ws.Stacks[i].Count > ws.Stacks[j].Count
			}
			return strings.Join(ws.Stacks[i].Frames, ";") < strings.Join(ws.Stacks[j].Frames, ";")
		})
		out = append(out, ws)
	}
	sortWorkloadStacks(out)
	return out, nil
}

// samplePeriodNS is the time one on-CPU sample stands for.
const samplePeriodNS = int64(1e9) / oncpu.SampleHz

// WritePprof writes stacks as a gzipped pprof profile, for `go tool pprof` or
// any tool that reads one. Each sample carries its workload as a label, and
// with onCPU it also carries the CPU time the sampling rate stands for.
func WritePprof(w io.Writer, profiles []WorkloadStacks, onCPU bool) error {
	p := &profile.Profile{
		SampleType: []*profile.ValueType{{Type: "samples", Unit: "count"}},
	}
	if onCPU {
		p.SampleType = append(p.SampleType, &profile.ValueType{Type: "cpu", Unit: "nanoseconds"})
		p.PeriodType = &profile.ValueType{Type: "cpu", Unit: "nanoseconds"}
		p.Period = samplePeriodNS
	}

	functions := map[string]*profile.Function{}
	locations := map[string]*profile.Location{}
	location := func(name string) *profile.Location {
		if loc, ok := locations[name]; ok {
			return loc
		}
		fn := &profile.Function{ID: uint64(len(functions) + 1), Name: name, SystemName: name}
		functions[name] = fn
		p.Function = append(p.Function, fn)
		loc := &profile.Location{ID: uint64(len(locations) + 1), Line: []profile.Line{{Function: fn}}}
		locations[name] = loc
		p.Location = append(p.Location, loc)
		return loc
	}

	for _, ws := range profiles {
		label := ws.Namespace + "/" + ws.Workload
		for _, s := range ws.Stacks {
			sample := &profile.Sample{
				Value: []int64{int64(s.Count)},
				Label: map[string][]string{"workload": {label}},
			}
			if onCPU {
				sample.Value = append(sample.Value, int64(s.Count)*samplePeriodNS)
			}
			for i := len(s.Frames) - 1; i >= 0; i-- {
				sample.Location = append(sample.Location, location(sanitize.Terminal(s.Frames[i])))
			}
			p.Sample = append(p.Sample, sample)
		}
	}
	return p.Write(w)
}
