package profiling

import (
	"strings"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/clock"
	"github.com/podtrace/podtrace/internal/events"
)

func TestCorrelate_NilEventSkipped(t *testing.T) {

	evts := []*events.Event{
		{Type: events.EventTCPSend, LatencyNS: 1_000_000_000, PID: 1},
		nil,
		{Type: events.EventPageFault, PID: 2},
	}
	cr := Correlate(evts, nil, nil, 100.0)
	if len(cr.SlowEvents) != 1 {
		t.Errorf("expected 1 slow event (nils skipped), got %d", len(cr.SlowEvents))
	}
}

func TestCorrelate_SlowEventsCappedAt20(t *testing.T) {
	var evts []*events.Event
	for i := 0; i < 30; i++ {
		evts = append(evts, &events.Event{
			Type:      events.EventTCPSend,
			LatencyNS: uint64(200_000_000 + i*1_000_000),
			PID:       uint32(i + 1),
		})
	}
	cr := Correlate(evts, nil, nil, 100.0)
	if len(cr.SlowEvents) != 20 {
		t.Errorf("expected slow events capped at 20, got %d", len(cr.SlowEvents))
	}

	for i := 1; i < len(cr.SlowEvents); i++ {
		if cr.SlowEvents[i].LatencyNS > cr.SlowEvents[i-1].LatencyNS {
			t.Fatalf("slow events not sorted by latency desc at %d", i)
		}
	}
}

func TestCorrelate_ProcessesSortedAndCappedAt10(t *testing.T) {
	var evts []*events.Event

	for pid := 1; pid <= 12; pid++ {
		for n := 0; n <= pid; n++ {
			evts = append(evts, &events.Event{
				Type:      events.EventSchedSwitch,
				PID:       uint32(pid),
				LatencyNS: uint64(1_000 * pid),
			})
		}
	}
	cr := Correlate(evts, nil, nil, 100.0)
	if len(cr.CPUHotProcesses) != 10 {
		t.Fatalf("expected CPU hot processes capped at 10, got %d", len(cr.CPUHotProcesses))
	}

	for i := 1; i < len(cr.CPUHotProcesses); i++ {
		if cr.CPUHotProcesses[i].SchedCount > cr.CPUHotProcesses[i-1].SchedCount {
			t.Fatalf("processes not sorted by sched count desc at %d", i)
		}
	}

	top := cr.CPUHotProcesses[0]
	if top.AvgBlockNS != float64(1_000*12) {
		t.Errorf("expected avg block %v, got %v", float64(1_000*12), top.AvgBlockNS)
	}
}

func TestCorrelate_WindowHotFrames(t *testing.T) {
	now := time.Now()
	slowTS := clock.WallToBPFTimestamp(now)
	inWindowTS := clock.WallToBPFTimestamp(now.Add(10 * time.Millisecond))

	evts := []*events.Event{
		{Type: events.EventTCPSend, LatencyNS: 500_000_000, PID: 1, Timestamp: slowTS},
	}

	base := uint64(0x100000)
	for i := 0; i < 5; i++ {
		off := base + uint64(i*100)
		evts = append(evts, &events.Event{
			Type:      events.EventSchedSwitch,
			PID:       uint32(100 + i),
			Timestamp: inWindowTS,
			Stack:     []uint64{off + 1, off + 2, off + 3, off + 4},
		})
	}

	evts = append(evts, &events.Event{
		Type:      events.EventSchedSwitch,
		PID:       200,
		Timestamp: inWindowTS,
		Stack:     []uint64{0, 0xAAAA1, 0xBBBB2, 0xCCCC3, 0xDDDD4},
	})

	cr := Correlate(evts, nil, nil, 100.0)
	if len(cr.HotFrames) == 0 {
		t.Fatal("expected hot frames from sched-switch inside the slow window")
	}
	if len(cr.HotFrames) > 10 {
		t.Errorf("expected hot frames capped at 10, got %d", len(cr.HotFrames))
	}
}

func TestGenerateSection_TruncationBranches(t *testing.T) {
	cr := &CorrelatedResult{
		PprofAvailable:  true,
		PodIP:           "10.0.0.9",
		PageFaultCounts: map[uint32]int{},
	}
	for i := 0; i < 6; i++ {
		cr.SlowEvents = append(cr.SlowEvents, &events.Event{
			Type:        events.EventTCPSend,
			LatencyNS:   uint64(1_000_000_000 - i),
			PID:         uint32(i + 1),
			ProcessName: "proc",
			Target:      "db:5432",
		})
	}
	for i := 0; i < 9; i++ {
		cr.HotFrames = append(cr.HotFrames, FrameCount{Frame: "0xdead", Count: 9 - i})
	}
	cr.HeapProfile = &ProfileResult{Available: true}
	for i := 0; i < 9; i++ {
		cr.HeapProfile.TopFunctions = append(cr.HeapProfile.TopFunctions,
			FunctionSample{Function: "pkg.F", Bytes: int64(9 - i), Count: 1})
	}
	for pid := uint32(1); pid <= 6; pid++ {
		cr.PageFaultCounts[pid] = int(pid) * 10
	}

	out := GenerateSection(cr, time.Second)
	for _, want := range []string{"Slow events", "hot frames", "heap alloc", "Page faults"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected section to contain %q, got:\n%s", want, out)
		}
	}
}
