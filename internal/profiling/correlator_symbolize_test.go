package profiling

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/clock"
	"github.com/gma1k/podtrace/internal/events"
)

type fakeResolver struct {
	mu    sync.Mutex
	calls int
	names map[uint64]string
}

func (f *fakeResolver) Resolve(_ context.Context, _ uint32, addr uint64) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if n, ok := f.names[addr]; ok {
		return n
	}
	return fmt.Sprintf("sym_%x", addr)
}

func TestHotFramesAreSymbolizedRatherThanPrintedAsHex(t *testing.T) {
	counts := map[frameAddr]int{
		{pid: 7, addr: 0xdeadbeef}: 5,
	}
	r := &fakeResolver{names: map[uint64]string{0xdeadbeef: "encoding/json.Marshal"}}

	got := symbolizeHotFrames(context.Background(), counts, r)

	if len(got) != 1 {
		t.Fatalf("got %d frames, want 1", len(got))
	}
	if got[0].Frame != "encoding/json.Marshal" {
		t.Errorf("frame = %q, want the resolved symbol.\n\nA raw address makes the report "+
			"unactionable: the reader has to run addr2line by hand against a binary that "+
			"may already be gone.", got[0].Frame)
	}
}

func TestAddressesInsideOneFunctionMergeIntoOneFrame(t *testing.T) {
	counts := map[frameAddr]int{
		{pid: 7, addr: 0x1000}: 3,
		{pid: 7, addr: 0x1008}: 2,
		{pid: 7, addr: 0x2000}: 4,
	}
	r := &fakeResolver{names: map[uint64]string{
		0x1000: "app.handle",
		0x1008: "app.handle",
		0x2000: "runtime.mallocgc",
	}}

	got := symbolizeHotFrames(context.Background(), counts, r)

	byName := map[string]int{}
	for _, f := range got {
		byName[f.Frame] += f.Count
	}
	if byName["app.handle"] != 5 {
		t.Errorf("app.handle = %d, want 5 (3+2).\n\nSeveral addresses inside one function "+
			"are one hot function; keeping them apart buries the culprit under its own "+
			"instruction offsets.", byName["app.handle"])
	}
	if got[0].Frame != "app.handle" {
		t.Errorf("ranked %q first, want app.handle once its addresses are merged", got[0].Frame)
	}
}

func TestSymbolizationIsBoundedByTheFrameCeiling(t *testing.T) {
	counts := map[frameAddr]int{}
	for i := 0; i < maxSymbolizedFrames*4; i++ {
		counts[frameAddr{pid: 1, addr: uint64(0x4000 + i*8)}] = i + 1
	}
	r := &fakeResolver{}

	symbolizeHotFrames(context.Background(), counts, r)

	if r.calls > maxSymbolizedFrames {
		t.Errorf("resolver called %d times for %d addresses, ceiling is %d.\n\nEach unseen "+
			"address forks addr2line, so an unbounded walk turns report generation into a "+
			"stall at the end of a session.", r.calls, len(counts), maxSymbolizedFrames)
	}
}

func TestTheHottestAddressesAreTheOnesResolved(t *testing.T) {
	counts := map[frameAddr]int{}
	for i := 0; i < maxSymbolizedFrames*2; i++ {
		counts[frameAddr{pid: 1, addr: uint64(0x8000 + i*8)}] = i + 1
	}
	hottest := uint64(0x8000 + (maxSymbolizedFrames*2-1)*8)
	r := &fakeResolver{names: map[uint64]string{hottest: "the_hot_one"}}

	got := symbolizeHotFrames(context.Background(), counts, r)

	found := false
	for _, f := range got {
		if f.Frame == "the_hot_one" {
			found = true
		}
	}
	if !found {
		t.Error("the highest-count address was not among those resolved.\n\nRanking has to " +
			"happen before symbolisation, or the ceiling spends the budget on whichever " +
			"addresses the map happened to iterate first.")
	}
}

func TestAnUnresolvableFrameStillReportsItsAddress(t *testing.T) {
	counts := map[frameAddr]int{{pid: 9, addr: 0xabc123}: 2}

	got := symbolizeHotFrames(context.Background(), counts, nil)

	if len(got) != 1 || !strings.Contains(got[0].Frame, "abc123") {
		t.Errorf("got %+v, want the raw address kept.\n\nA process that exited before the "+
			"report is generated cannot be symbolised, and dropping the frame loses the "+
			"only evidence there was", got)
	}
}

func TestNoFramesYieldsNoSection(t *testing.T) {
	if got := symbolizeHotFrames(context.Background(), nil, &fakeResolver{}); got != nil {
		t.Errorf("got %+v, want nil for an empty capture", got)
	}
}

func TestStacksAreAggregatedBelowTheSchedulerFrames(t *testing.T) {
	now := clock.WallToBPFTimestamp(time.Now())

	deep := make([]uint64, 0, maxCorrelatedStackDepth)
	for i := 0; i < maxCorrelatedStackDepth; i++ {
		deep = append(deep, uint64(0x5000+i*8))
	}

	evts := []*events.Event{
		{Type: events.EventTCPSend, LatencyNS: 500_000_000, PID: 1, Timestamp: now},
		{Type: events.EventSchedSwitch, PID: 1, LatencyNS: 1_000, Timestamp: now, Stack: deep},
	}

	named := map[uint64]string{}
	for i, a := range deep {
		named[a] = fmt.Sprintf("frame_%02d", i)
	}
	r := &fakeResolver{names: named}

	cr := Correlate(context.Background(), evts, nil, nil, 100.0, r)

	seen := map[string]bool{}
	for _, f := range cr.HotFrames {
		seen[f.Frame] = true
	}
	if !seen["frame_05"] {
		t.Errorf("frame_05 missing from HotFrames (got %v).\n\nOnly the top three frames "+
			"used to be aggregated, and at sched_switch those are the scheduler and "+
			"runtime path -- the function actually responsible sits below them, so a "+
			"three-frame window names the kernel every time.", seen)
	}
	if len(seen) <= 3 {
		t.Errorf("only %d distinct frames aggregated; the stack was walked no deeper than "+
			"the old three-frame window", len(seen))
	}
}

func TestFrameOrderIsStableAcrossRuns(t *testing.T) {
	counts := map[frameAddr]int{}
	for i := 0; i < 20; i++ {
		counts[frameAddr{pid: uint32(i%3 + 1), addr: uint64(0x9000 + i*8)}] = 7
	}

	first := symbolizeHotFrames(context.Background(), counts, &fakeResolver{})
	for run := 0; run < 5; run++ {
		got := symbolizeHotFrames(context.Background(), counts, &fakeResolver{})
		if len(got) != len(first) {
			t.Fatalf("run %d returned %d frames, first returned %d", run, len(got), len(first))
		}
		for i := range got {
			if got[i] != first[i] {
				t.Fatalf("run %d differs at %d: %+v vs %+v.\n\nEqual counts must break on "+
					"pid then address, or map iteration order decides which frames make "+
					"the cut and two reports from one capture disagree.", run, i, got[i], first[i])
			}
		}
	}
}

func TestDeepStacksSkipZeroFrames(t *testing.T) {
	now := clock.WallToBPFTimestamp(time.Now())
	evts := []*events.Event{
		{Type: events.EventTCPSend, LatencyNS: 500_000_000, PID: 4, Timestamp: now},
		{Type: events.EventSchedSwitch, PID: 4, LatencyNS: 1_000, Timestamp: now,
			Stack: []uint64{0x1100, 0, 0x1200, 0, 0}},
	}

	cr := Correlate(context.Background(), evts, nil, nil, 100.0,
		&fakeResolver{names: map[uint64]string{0x1100: "a", 0x1200: "b"}})

	for _, f := range cr.HotFrames {
		if f.Frame == "0x0" || f.Frame == "sym_0" {
			t.Errorf("a zero frame reached the report: %+v; BPF pads short stacks with "+
				"zeroes and counting them ranks padding above real frames", cr.HotFrames)
		}
	}
	if len(cr.HotFrames) != 2 {
		t.Errorf("got %d frames, want 2 real ones: %+v", len(cr.HotFrames), cr.HotFrames)
	}
}

func TestStackAggregationStopsAtTheDepthCap(t *testing.T) {
	now := clock.WallToBPFTimestamp(time.Now())

	// Deeper than the cap, so the frames past it must be ignored.
	deep := make([]uint64, 0, maxCorrelatedStackDepth*2)
	for i := 0; i < maxCorrelatedStackDepth*2; i++ {
		deep = append(deep, uint64(0x7000+i*8))
	}
	beyondCap := deep[maxCorrelatedStackDepth]

	evts := []*events.Event{
		{Type: events.EventTCPSend, LatencyNS: 500_000_000, PID: 3, Timestamp: now},
		{Type: events.EventSchedSwitch, PID: 3, LatencyNS: 1_000, Timestamp: now, Stack: deep},
	}

	named := map[uint64]string{}
	for i, a := range deep {
		named[a] = fmt.Sprintf("f%02d", i)
	}

	cr := Correlate(context.Background(), evts, nil, nil, 100.0, &fakeResolver{names: named})

	for _, f := range cr.HotFrames {
		if f.Frame == named[beyondCap] {
			t.Errorf("frame %q past the depth cap was aggregated.\n\nThe cap is what keeps "+
				"a pathological stack from dominating the ranking and paying symbolisation "+
				"for frames nobody reads.", f.Frame)
		}
	}
}
