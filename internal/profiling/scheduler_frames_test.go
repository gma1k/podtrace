package profiling

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func goServiceNames() map[uint64]string {
	return map[uint64]string{
		0x10: "runtime.schedule",
		0x20: "runtime.park_m",
		0x30: "runtime.mcall",
		0x40: "runtime.goexit.abi0",
		0x50: "main.(*Checkout).price",
		0x60: "runtime.chanrecv",
		0x70: "sync.runtime_Semacquire",
		0x80: "encoding/json.Marshal",
	}
}

func TestSchedulerFramesAreHiddenAndCounted(t *testing.T) {
	counts := map[frameAddr]int{
		{pid: 1, addr: 0x10}: 90,
		{pid: 1, addr: 0x20}: 90,
		{pid: 1, addr: 0x30}: 90,
		{pid: 1, addr: 0x40}: 90,
		{pid: 1, addr: 0x50}: 12,
		{pid: 1, addr: 0x80}: 7,
	}
	frames, hidden := symbolizeHotFramesHidingScheduler(context.Background(), counts,
		&fakeResolver{names: goServiceNames()})

	if hidden != 360 {
		t.Errorf("hidden = %d, want 360 (four scheduler frames of 90 hits each)", hidden)
	}
	if len(frames) != 2 || frames[0].Frame != "main.(*Checkout).price" || frames[1].Frame != "encoding/json.Marshal" {
		t.Errorf("frames = %+v, want the two application frames in rank order.\n\n"+
			"Every sched_switch stack passes through the scheduler, so without the filter "+
			"runtime.schedule and runtime.park_m lead every profile and the frame that "+
			"answers where the time goes is pushed down or off the list.", frames)
	}
}

func TestBlockingPointsStayVisible(t *testing.T) {
	counts := map[frameAddr]int{
		{pid: 1, addr: 0x60}: 40,
		{pid: 1, addr: 0x70}: 30,
		{pid: 1, addr: 0x10}: 50,
	}
	frames, _ := symbolizeHotFramesHidingScheduler(context.Background(), counts,
		&fakeResolver{names: goServiceNames()})

	got := map[string]bool{}
	for _, f := range frames {
		got[f.Frame] = true
	}
	for _, want := range []string{"runtime.chanrecv", "sync.runtime_Semacquire"} {
		if !got[want] {
			t.Errorf("%s was hidden; a blocking point says what the code waits on and "+
				"must stay in the profile (got %+v)", want, frames)
		}
	}
}

func TestAnABISuffixedSchedulerFrameIsStillRecognised(t *testing.T) {
	for _, name := range []string{"runtime.goexit.abi0", "runtime.mcall.abi1", "runtime.park_m"} {
		if !isSchedulerFrame(name) {
			t.Errorf("%s was not recognised as scheduler machinery", name)
		}
	}
	for _, name := range []string{"main.schedule", "runtime.mallocgc", "0x4a2f10", ""} {
		if isSchedulerFrame(name) {
			t.Errorf("%q was treated as scheduler machinery", name)
		}
	}
}

func TestAWorkloadProfileReportsTheSchedulerHitsItHid(t *testing.T) {
	p := NewContinuousProfiler(namingFactory(&fakeResolver{names: goServiceNames()}), nil)
	_ = p.Export(context.Background(), []*events.Event{
		schedSample("shop", "checkout", 1, 0x10, 0x20, 0x50),
		schedSample("shop", "checkout", 1, 0x10, 0x20, 0x50),
	})

	got := p.Snapshot(context.Background())
	if len(got) != 1 {
		t.Fatalf("got %d workloads, want 1", len(got))
	}
	if got[0].SchedulerFrames != 4 {
		t.Errorf("SchedulerFrames = %d, want 4", got[0].SchedulerFrames)
	}
	if len(got[0].Frames) != 1 || got[0].Frames[0].Frame != "main.(*Checkout).price" {
		t.Errorf("frames = %+v, want only the application frame", got[0].Frames)
	}
	if got[0].Samples != 6 {
		t.Errorf("Samples = %d, want 6: hiding frames from the list must not change the "+
			"sample count the profile is weighted by", got[0].Samples)
	}

	raw, err := json.Marshal(got[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"schedulerFrames":4`) {
		t.Errorf("the /profile JSON does not carry the hidden count: %s", raw)
	}
}

func TestTheCorrelatedReportSaysWhatItHid(t *testing.T) {
	withApp := GenerateSection(&CorrelatedResult{
		HotFrames:       []FrameCount{{Frame: "main.(*Checkout).price", Count: 12}},
		SchedulerFrames: 360,
	}, 0)
	if !strings.Contains(withApp, "360 Go scheduler frame hits") {
		t.Errorf("the report did not say scheduler frames were hidden:\n%s", withApp)
	}

	onlyScheduler := GenerateSection(&CorrelatedResult{SchedulerFrames: 50}, 0)
	if !strings.Contains(onlyScheduler, "50 Go scheduler frame hits") {
		t.Errorf("a window whose stacks were all scheduler printed nothing, which reads as "+
			"no stacks captured at all:\n%s", onlyScheduler)
	}

	none := GenerateSection(&CorrelatedResult{HotFrames: []FrameCount{{Frame: "f", Count: 1}}}, 0)
	if strings.Contains(none, "scheduler frame hits") {
		t.Errorf("a hidden-frames line was printed when nothing was hidden:\n%s", none)
	}
}

func TestTheSchedulerIdleLoopIsHiddenButASocketWaitIsNot(t *testing.T) {
	for _, name := range []string{"runtime.netpoll", "runtime.stealWork", "runtime.notetsleep", "runtime.checkTimers"} {
		if !isSchedulerFrame(name) {
			t.Errorf("%s is the scheduler's idle loop and should be hidden; on kind it "+
				"led cilium's profile once runtime.schedule was gone", name)
		}
	}
	for _, name := range []string{"runtime.netpollblock", "internal/poll.(*FD).Read", "runtime.selectgo"} {
		if isSchedulerFrame(name) {
			t.Errorf("%s is a goroutine waiting on its own work and must stay visible", name)
		}
	}
}
