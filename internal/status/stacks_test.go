package status

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/pprof/profile"

	"github.com/gma1k/podtrace/internal/profiling"
)

func twoAgents() []Agent {
	return []Agent{{Name: "a", Node: "n1", Ready: true, Port: 9090}, {Name: "b", Node: "n2", Ready: true, Port: 9090}}
}

func pprofBody(t *testing.T, onCPU bool, count int) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := profiling.WritePprof(&buf, []profiling.WorkloadStacks{{Namespace: "shop", Workload: "checkout",
		Stacks: []profiling.NamedStack{{Frames: []string{"main", "price"}, Count: count}}}}, onCPU); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestFoldedStacksFromEveryNodeAreSummed(t *testing.T) {
	fc := &fakeCluster{agents: twoAgents(), stacks: map[string][]byte{
		"a": []byte("shop/checkout;main;price 3"),
		"b": []byte("shop/checkout;main;price 2\nshop/checkout;main;tax 1\n"),
	}}
	var out bytes.Buffer
	failed, err := (&Collector{Cluster: fc}).WriteStacks(context.Background(), &out, StackFormatFolded, profiling.StackSelection{})
	if err != nil || len(failed) != 0 {
		t.Fatalf("WriteStacks = %v, %v", failed, err)
	}
	if want := "shop/checkout;main;price 5\nshop/checkout;main;tax 1\n"; out.String() != want {
		t.Errorf("folded = %q, want %q", out.String(), want)
	}
}

func TestPprofProfilesFromEveryNodeAreMerged(t *testing.T) {
	fc := &fakeCluster{agents: twoAgents(), stacks: map[string][]byte{"a": pprofBody(t, true, 3), "b": pprofBody(t, true, 2)}}
	var out bytes.Buffer
	if _, err := (&Collector{Cluster: fc}).WriteStacks(context.Background(), &out, StackFormatPprof, profiling.StackSelection{}); err != nil {
		t.Fatal(err)
	}
	p, err := profile.ParseData(out.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Sample) != 1 || p.Sample[0].Value[0] != 5 {
		t.Errorf("merged samples = %v", p.Sample)
	}
}

func TestAnAgentThatFailsIsAWarningNotAnError(t *testing.T) {
	fc := &fakeCluster{agents: twoAgents(), stacks: map[string][]byte{"b": []byte("shop/checkout;f 1\n")},
		stackErr: map[string]error{"a": errors.New("proxy\nrefused")}}
	var out bytes.Buffer
	failed, err := (&Collector{Cluster: fc}).WriteStacks(context.Background(), &out, StackFormatFolded, profiling.StackSelection{})
	if err != nil || len(failed) != 1 || !strings.Contains(failed[0], "no stacks from a on n1: proxy refused") {
		t.Errorf("WriteStacks = %q, %v", failed, err)
	}
}

func TestNoStacksAnywhereIsReported(t *testing.T) {
	for _, format := range []StackFormat{StackFormatFolded, StackFormatPprof} {
		fc := &fakeCluster{agents: twoAgents(), stacks: map[string][]byte{"a": pprofEmpty(t, format)}}
		if _, err := (&Collector{Cluster: fc}).WriteStacks(context.Background(), &bytes.Buffer{}, format, profiling.StackSelection{}); !errors.Is(err, ErrNoStacks) {
			t.Errorf("%s: err = %v, want ErrNoStacks", format, err)
		}
	}
}

func pprofEmpty(t *testing.T, format StackFormat) []byte {
	if format == StackFormatFolded {
		return nil
	}
	var buf bytes.Buffer
	_ = profiling.WritePprof(&buf, nil, true)
	return buf.Bytes()
}

func TestUnreadableOrIncompatibleStacksAreErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		format StackFormat
		bodies map[string][]byte
		want   string
	}{
		"bad folded":   {StackFormatFolded, map[string][]byte{"a": []byte("no count here")}, "read folded"},
		"bad pprof":    {StackFormatPprof, map[string][]byte{"a": []byte("not a profile")}, "read pprof"},
		"mixed source": {StackFormatPprof, map[string][]byte{"a": pprofBody(t, true, 1), "b": pprofBody(t, false, 1)}, "-o folded"},
	} {
		t.Run(name, func(t *testing.T) {
			fc := &fakeCluster{agents: twoAgents(), stacks: tc.bodies}
			_, err := (&Collector{Cluster: fc}).WriteStacks(context.Background(), &bytes.Buffer{}, tc.format, profiling.StackSelection{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestStacksNeedTheAgentList(t *testing.T) {
	fc := &fakeCluster{agentsErr: errors.New("forbidden")}
	if _, err := (&Collector{Cluster: fc}).WriteStacks(context.Background(), &bytes.Buffer{}, StackFormatFolded, profiling.StackSelection{}); err == nil {
		t.Error("no error")
	}
}
