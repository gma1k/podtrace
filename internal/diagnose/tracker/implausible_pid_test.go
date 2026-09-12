package tracker

import (
	"testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestAnImpossiblePIDIsNotRankedAsAProcess(t *testing.T) {
	got := AnalyzeProcessActivity([]*events.Event{
		{Type: events.EventRead, PID: 4242, ProcessName: "poolapp"},
		{Type: events.EventRead, PID: 4242, ProcessName: "poolapp"},
		{Type: events.EventRead, PID: 7368801, ProcessName: "app"},
	})

	for _, info := range got {
		if info.Pid == 7368801 {
			t.Errorf("pid 7368801 was ranked as a process.\n\nIt exceeds the kernel's "+
				"pid_max, so no such process can exist; the value is the bytes of a comm "+
				"read as an integer. Every pid-keyed cache and the cgroup filter already "+
				"reject it via validation.ValidatePID, and getProcessNameFromProc in this "+
				"same file does too -- so it reaches the report with no name and names a "+
				"process that has never run. got %+v", got)
		}
	}
}

func TestRealPIDsAreStillRanked(t *testing.T) {
	got := AnalyzeProcessActivity([]*events.Event{
		{Type: events.EventRead, PID: 4242, ProcessName: "poolapp"},
		{Type: events.EventRead, PID: 7368801, ProcessName: "app"},
	})

	if len(got) != 1 {
		t.Fatalf("got %d ranked processes, want 1: %+v", len(got), got)
	}
	if got[0].Pid != 4242 || got[0].Name != "poolapp" {
		t.Errorf("ranked %+v, want pid 4242 named poolapp", got[0])
	}
}

func TestPIDZeroIsStillRanked(t *testing.T) {
	got := AnalyzeProcessActivity([]*events.Event{
		{Type: events.EventRead, PID: 0, ProcessName: ""},
		{Type: events.EventRead, PID: 4242, ProcessName: "poolapp"},
	})

	found := false
	for _, info := range got {
		if info.Pid == 0 {
			found = true
		}
	}
	if !found {
		t.Errorf("pid 0 was dropped from the ranking.\n\nIt is not a corrupted value: "+
			"the cgroup_skb producers cannot call bpf_get_current_comm, so DNS and QUIC "+
			"events legitimately carry no pid. Folding them away would delete the whole "+
			"Process Activity section for a workload whose traffic is mostly network, "+
			"and hide how many events could not be attributed. got %+v", got)
	}
}

func TestPercentagesStillCountEveryEvent(t *testing.T) {
	got := AnalyzeProcessActivity([]*events.Event{
		{Type: events.EventRead, PID: 4242, ProcessName: "poolapp"},
		{Type: events.EventRead, PID: 7368801, ProcessName: "app"},
	})

	if len(got) != 1 {
		t.Fatalf("got %d ranked, want 1", len(got))
	}
	if got[0].Percentage != 50 {
		t.Errorf("percentage = %v, want 50.\n\nThe denominator stays the total number of "+
			"events collected, so excluding an unattributable pid from the ranking must "+
			"not silently inflate the share of the processes that remain.", got[0].Percentage)
	}
}

func TestTheExcludedEventIsStillCounted(t *testing.T) {
	got := AnalyzeProcessActivity([]*events.Event{
		{Type: events.EventRead, PID: 4242, ProcessName: "poolapp"},
		{Type: events.EventRead, PID: 7368801, ProcessName: "app"},
		{Type: events.EventRead, PID: 7368801, ProcessName: "app"},
	})

	if len(got) != 1 {
		t.Fatalf("got %d ranked, want 1", len(got))
	}
	if got[0].Count != 1 {
		t.Errorf("count = %d, want 1; the real process must not absorb the excluded "+
			"events", got[0].Count)
	}
	if got[0].Percentage < 33 || got[0].Percentage > 34 {
		t.Errorf("percentage = %v, want ~33.3 (1 of 3 collected events).\n\nThe "+
			"denominator is every event collected, so the two unattributable ones still "+
			"count against the total rather than vanishing from the accounting.",
			got[0].Percentage)
	}
}
