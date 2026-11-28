package tracer

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/gma1k/podtrace/internal/ebpf/probes"
)

type pidLinks map[uint32][]*fakeLink

func (p pidLinks) closes(pid uint32) int {
	n := 0
	for _, l := range p[pid] {
		n += int(l.closes.Load())
	}
	return n
}

func withPIDAttach(t *testing.T, starts func(pid uint32) (uint64, bool)) pidLinks {
	t.Helper()
	attached := pidLinks{}
	origAttach, origStart := attachPIDGroupUprobes, processStartTime
	attachPIDGroupUprobes = func(_ *ebpf.Collection, _ probes.ProbeGroup, _ string, pid uint32, _ *probes.AttachedFiles) []link.Link {
		l := &fakeLink{}
		attached[pid] = append(attached[pid], l)
		return []link.Link{l}
	}
	processStartTime = starts
	t.Cleanup(func() { attachPIDGroupUprobes, processStartTime = origAttach, origStart })
	return attached
}

func TestLinksAttachedThroughAReusedPidAreDetached(t *testing.T) {
	now := map[uint32]uint64{10: 100, 11: 999}
	attached := withPIDAttach(t, func(pid uint32) (uint64, bool) { v, ok := now[pid]; return v, ok })
	tr := &Tracer{collection: &ebpf.Collection{}}
	ls := tr.attachContainerGroupUprobes(probes.GroupTLS, "c", []uint32{10, 11}, nil, processStarts{10: 100, 11: 200})
	if len(ls) != 1 || ls[0] != attached[10][0] {
		t.Fatalf("links = %v, want only the link of pid 10, whose process is unchanged", ls)
	}
	if attached.closes(10) != 0 || attached.closes(11) != 1 {
		t.Errorf("closes: pid 10 %d, pid 11 %d; want pid 11's link closed once", attached.closes(10), attached.closes(11))
	}
}

func TestLinksOfAProcessThatExitedOrWasNeverTimedAreKept(t *testing.T) {
	withPIDAttach(t, func(uint32) (uint64, bool) { return 0, false })
	tr := &Tracer{collection: &ebpf.Collection{}}
	ls := tr.attachContainerGroupUprobes(probes.GroupPool, "c", []uint32{10, 11}, nil, processStarts{10: 100})
	if len(ls) != 2 {
		t.Fatalf("links = %v, want both kept: an exited process had its own files opened", ls)
	}
}

func TestSetContainerTargetsChecksEachPidAgainstItsEnumeratedStartTime(t *testing.T) {
	calls := map[uint32]int{}
	attached := withPIDAttach(t, func(pid uint32) (uint64, bool) {
		calls[pid]++
		if pid == 21 && calls[pid] > 1 {
			return 999, true
		}
		return 100, true
	})
	tr := &Tracer{collection: &ebpf.Collection{}}
	if err := tr.SetContainerTargets([]ContainerProbeTarget{{ID: "c", PIDs: []uint32{20, 21}}}); err != nil {
		t.Fatal(err)
	}
	set := tr.containerUprobes["c"]
	if set == nil || set.started[20] != 100 || set.started[21] != 100 {
		t.Fatalf("set = %+v, want both enumerated start times recorded", set)
	}
	if attached.closes(20) != 0 {
		t.Error("the links of an unchanged process were closed")
	}
	if len(attached[21]) != len(containerUprobeGroups) || attached.closes(21) != len(containerUprobeGroups) {
		t.Errorf("pid 21 attached %d and closed %d links, want every group's link (%d) closed after its pid was reused",
			len(attached[21]), attached.closes(21), len(containerUprobeGroups))
	}
}

func TestReattachChecksPidsAgainstTheirEnumeratedStartTimes(t *testing.T) {
	attached := withPIDAttach(t, func(uint32) (uint64, bool) { return 999, true })
	tr := &Tracer{collection: &ebpf.Collection{}, containerUprobes: map[string]*containerUprobeSet{
		"c": {pids: []uint32{30}, started: processStarts{30: 100}},
	}}
	if n := tr.reattachContainerGroupUprobes(probes.GroupTLS); n != 0 {
		t.Fatalf("reattached %d links through a reused pid", n)
	}
	if attached.closes(30) != 1 {
		t.Errorf("the link attached through the reused pid was closed %d times, want 1", attached.closes(30))
	}
}

func TestRecordProcessStartsSkipsUnreadablePids(t *testing.T) {
	withPIDAttach(t, func(pid uint32) (uint64, bool) { return uint64(pid) * 10, pid != 2 })
	got := recordProcessStarts([]uint32{1, 2, 3})
	if len(got) != 2 || got[1] != 10 || got[3] != 30 {
		t.Fatalf("recordProcessStarts = %v, want pids 1 and 3 only", got)
	}
}
