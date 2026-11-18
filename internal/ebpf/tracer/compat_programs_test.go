package tracer

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
)

func compatSpec() *ebpf.CollectionSpec {
	return &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		"dns_egress":                 {Name: "dns_egress"},
		"dns_egress__compat":         {Name: "dns_egress__compat", SectionName: "compat"},
		"tracepoint_oom_mark_victim": {Name: "tracepoint_oom_mark_victim"},
		"tracepoint_oom_mark_victim__compat": {
			Name: "tracepoint_oom_mark_victim__compat", SectionName: "compat",
		},
		"orphan__compat":     {Name: "orphan__compat"},
		"kprobe_tcp_sendmsg": {Name: "kprobe_tcp_sendmsg"},
	}}
}

func TestSplitCompatProgramsRemovesEveryVariant(t *testing.T) {
	spec := compatSpec()
	compat := splitCompatPrograms(spec)
	for name := range spec.Programs {
		if len(name) > len(compatSuffix) && name[len(name)-len(compatSuffix):] == compatSuffix {
			t.Errorf("%s is still in the spec", name)
		}
	}
	if len(compat) != 2 || compat["dns_egress"] == nil || compat["tracepoint_oom_mark_victim"] == nil {
		t.Errorf("compat = %v, want dns_egress and tracepoint_oom_mark_victim", compat)
	}
	if _, ok := compat["orphan"]; ok {
		t.Error("a variant without its preferred program must be dropped, not kept")
	}
}

func TestFailedProgramReadsTheCollectionError(t *testing.T) {
	err := fmt.Errorf("program dns_egress: load program: invalid argument: unknown func")
	if got := failedProgram(err); got != "dns_egress" {
		t.Errorf("failedProgram = %q, want dns_egress", got)
	}
	if got := failedProgram(errors.New("map events: create: invalid argument")); got != "" {
		t.Errorf("failedProgram = %q for a map error, want empty", got)
	}
	if got := failedProgram(nil); got != "" {
		t.Errorf("failedProgram(nil) = %q", got)
	}
}

func TestCompatFallbackSwapsOnlyTheRejectedProgram(t *testing.T) {
	spec := compatSpec()
	var attempts []map[string]string
	create := func(s *ebpf.CollectionSpec, _ ebpf.CollectionOptions) (*ebpf.Collection, error) {
		seen := map[string]string{}
		for key, p := range s.Programs {
			seen[key] = p.SectionName
		}
		attempts = append(attempts, seen)
		if seen["dns_egress"] != "compat" {
			return nil, errors.New("program dns_egress: load program: unknown func bpf_get_current_pid_tgid#14")
		}
		return &ebpf.Collection{}, nil
	}
	if _, err := withCompatFallback(create)(spec, ebpf.CollectionOptions{}); err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(attempts) != 2 {
		t.Fatalf("attempts = %d, want 2", len(attempts))
	}
	if attempts[1]["dns_egress"] != "compat" {
		t.Error("the retry must load the variant under the preferred key")
	}
	if spec.Programs["dns_egress"] == nil || spec.Programs["dns_egress"].Name != "dns_egress" {
		t.Error("the spec must hold the variant under the preferred key")
	}
	if spec.Programs["tracepoint_oom_mark_victim"].SectionName == "compat" {
		t.Error("a program the kernel accepted must not be swapped")
	}
}

func TestCompatFallbackReturnsOtherFailuresUnchanged(t *testing.T) {
	want := errors.New("program kprobe_tcp_sendmsg: load program: permission denied")
	calls := 0
	create := func(*ebpf.CollectionSpec, ebpf.CollectionOptions) (*ebpf.Collection, error) {
		calls++
		return nil, want
	}
	_, err := withCompatFallback(create)(compatSpec(), ebpf.CollectionOptions{})
	if !errors.Is(err, want) || calls != 1 {
		t.Errorf("err = %v after %d calls, want the original error after 1", err, calls)
	}
}

func TestCompatFallbackSurvivesARetryOfTheSameSpec(t *testing.T) {
	spec := compatSpec()
	load := withCompatFallback(func(s *ebpf.CollectionSpec, _ ebpf.CollectionOptions) (*ebpf.Collection, error) {
		if s.Programs["tracepoint_oom_mark_victim"].SectionName != "compat" {
			return nil, errors.New("program tracepoint_oom_mark_victim: load program: calling kernel function bpf_task_from_pid is not allowed")
		}
		return &ebpf.Collection{}, nil
	})
	if _, err := load(spec, ebpf.CollectionOptions{}); err != nil {
		t.Fatalf("first load: %v", err)
	}
	if _, err := load(spec, ebpf.CollectionOptions{}); err != nil {
		t.Fatalf("a second load of the same spec must still succeed: %v", err)
	}
}
