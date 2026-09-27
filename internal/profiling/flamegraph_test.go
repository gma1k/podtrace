package profiling

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/pprof/profile"

	"github.com/gma1k/podtrace/internal/ebpf/oncpu"
)

func twoWorkloadProfiler() *ContinuousProfiler {
	p := onCPUProfiler()
	p.IngestOnCPU(oncpu.Drained{Samples: []oncpu.Sample{
		{CgroupID: 7, PID: 1, Stack: []uint64{0x100, 0x200}, Count: 3},
		{CgroupID: 7, PID: 1, Stack: []uint64{0x300, 0x200}, Count: 1},
		{CgroupID: 8, PID: 2, Stack: []uint64{0x400}, Count: 2},
	}})
	return p
}

func TestStacksAreNamedOutermostFirstAndFiltered(t *testing.T) {
	p := twoWorkloadProfiler()
	all := p.Stacks(context.Background(), StackSelection{})
	if len(all) != 2 || all[0].Workload != "cart" || all[1].Workload != "checkout" {
		t.Fatalf("stacks = %+v", all)
	}
	first := all[1].Stacks[0]
	if first.Count != 3 || strings.Join(first.Frames, ";") != "fn_200;fn_100" {
		t.Errorf("busiest checkout stack = %+v, want the caller before the frame it called", first)
	}
	one := p.Stacks(context.Background(), StackSelection{Namespace: "shop", Workload: "cart"})
	if len(one) != 1 || one[0].Workload != "cart" {
		t.Errorf("filtered = %+v", one)
	}
	if none := p.Stacks(context.Background(), StackSelection{Namespace: "other"}); len(none) != 0 {
		t.Errorf("another namespace's filter returned %+v", none)
	}
}

func TestFoldedStacksRoundTripAndMerge(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFolded(&buf, twoWorkloadProfiler().Stacks(context.Background(), StackSelection{})); err != nil {
		t.Fatal(err)
	}
	want := "shop/cart;fn_400 2\nshop/checkout;fn_200;fn_100 3\nshop/checkout;fn_200;fn_300 1\n"
	if buf.String() != want {
		t.Errorf("folded =\n%s\nwant\n%s", buf.String(), want)
	}

	merged, err := ParseFolded(strings.NewReader(buf.String() + "\n" + buf.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(merged) != 2 || merged[1].Stacks[0].Count != 6 || merged[1].Stacks[1].Count != 2 {
		t.Errorf("merged = %+v, want each stack summed across both copies", merged)
	}
}

func TestAFrameNameCannotBreakTheFoldedFormat(t *testing.T) {
	var buf bytes.Buffer
	_ = WriteFolded(&buf, []WorkloadStacks{{Namespace: "a", Workload: "b", Stacks: []NamedStack{
		{Frames: []string{"evil;frame\n\x1b[31m", "ok"}, Count: 1},
	}}})
	if got := buf.String(); strings.Count(got, "\n") != 1 || strings.Count(got, ";") != 2 || strings.Contains(got, "\x1b") {
		t.Errorf("folded = %q; a symbol from the workload's binary forged a frame or a line", got)
	}
}

func TestMalformedFoldedInputIsRejected(t *testing.T) {
	for _, bad := range []string{"a/b;f", "a/b;f x", "a/b;f -1", "nowl;f 1", "a/b 1"} {
		if _, err := ParseFolded(strings.NewReader(bad)); err == nil {
			t.Errorf("ParseFolded(%q) accepted it", bad)
		}
	}
	if _, err := ParseFolded(strings.NewReader(strings.Repeat("x", maxFoldedLineBytes+1))); err == nil {
		t.Error("an over-long line was accepted")
	}
}

func TestPprofCarriesTheStacksAndTheirCPUTime(t *testing.T) {
	var buf bytes.Buffer
	if err := WritePprof(&buf, twoWorkloadProfiler().Stacks(context.Background(), StackSelection{}), true); err != nil {
		t.Fatal(err)
	}
	p, err := profile.ParseData(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.SampleType) != 2 || p.SampleType[1].Type != "cpu" || p.Period != samplePeriodNS {
		t.Errorf("sample types = %v, period = %d", p.SampleType, p.Period)
	}
	if len(p.Sample) != 3 || len(p.Function) != 4 {
		t.Fatalf("%d samples and %d functions", len(p.Sample), len(p.Function))
	}
	s := p.Sample[1]
	if s.Value[0] != 3 || s.Value[1] != 3*samplePeriodNS || s.Label["workload"][0] != "shop/checkout" ||
		s.Location[0].Line[0].Function.Name != "fn_100" {
		t.Errorf("sample = %+v; pprof lists the innermost frame first", s)
	}
}

func TestPprofFromSchedSwitchStacksClaimsNoCPUTime(t *testing.T) {
	var buf bytes.Buffer
	_ = WritePprof(&buf, []WorkloadStacks{{Namespace: "a", Workload: "b", Stacks: []NamedStack{{Frames: []string{"f"}, Count: 1}}}}, false)
	p, err := profile.ParseData(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.SampleType) != 1 || (p.PeriodType != nil && p.PeriodType.Type != "") || p.Period != 0 {
		t.Errorf("sample types = %v; a sched_switch stack is not a unit of CPU time", p.SampleType)
	}
}

type failAfter struct{ n int }

func (w *failAfter) Write(p []byte) (int, error) {
	if w.n <= 0 {
		return 0, errors.New("closed")
	}
	w.n--
	return len(p), nil
}

func TestAFoldedWriteFailureIsReturned(t *testing.T) {
	big := make([]NamedStack, 5000)
	for i := range big {
		big[i] = NamedStack{Frames: []string{strings.Repeat("f", 20)}, Count: 1}
	}
	if err := WriteFolded(&failAfter{}, []WorkloadStacks{{Namespace: "a", Workload: "b", Stacks: big}}); err == nil {
		t.Error("a failure while writing lines was swallowed")
	}
	small := []WorkloadStacks{{Namespace: "a", Workload: "b", Stacks: big[:1]}}
	if err := WriteFolded(&failAfter{}, small); err == nil {
		t.Error("a failure on the final flush was swallowed")
	}
}

func TestEquallyBusyStacksAndWorkloadsSortStably(t *testing.T) {
	merged, err := ParseFolded(strings.NewReader("zeta/a;f 1\nalpha/a;g 1\nalpha/a;f 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if merged[0].Namespace != "alpha" || merged[0].Stacks[0].Frames[0] != "f" || merged[1].Namespace != "zeta" {
		t.Errorf("merged = %+v", merged)
	}

	a, _ := newStackKey(2, []uint64{0x1})
	b, _ := newStackKey(1, []uint64{0x1})
	c, _ := newStackKey(1, []uint64{0x2})
	ranked := rankedStacks(map[stackKey]int{a: 1, b: 1, c: 1})
	if ranked[0] != b || ranked[1] != c || ranked[2] != a {
		t.Errorf("ties are not broken by pid then address: %v", ranked)
	}
}
