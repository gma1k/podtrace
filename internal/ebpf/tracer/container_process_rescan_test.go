package tracer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/gma1k/podtrace/internal/ebpf/probes"
)

const rescanContainerID = "abcdefabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123"

type rescanWorld struct {
	t         *testing.T
	cgroupDir string
	idents    map[uint32]processIdentity
	full      map[uint32]int
	scoped    pidLinks
	tr        *Tracer
}

func newRescanWorld(t *testing.T, idents map[uint32]processIdentity) *rescanWorld {
	t.Helper()
	w := &rescanWorld{t: t, idents: idents, full: map[uint32]int{}, scoped: pidLinks{}}
	pids := make([]uint32, 0, len(idents))
	for pid := range idents {
		pids = append(pids, pid)
	}
	slices.Sort(pids)
	w.cgroupDir = fakeContainerProc(t, rescanContainerID, pids, map[uint32]string{})
	origIdent, origAttach, origScoped, origStart := readProcessIdentity, attachPIDGroupUprobes, attachProcessScopedProbes, processStartTime
	readProcessIdentity = func(pid uint32) (processIdentity, bool) {
		ident, ok := w.idents[pid]
		return ident, ok
	}
	processStartTime = func(pid uint32) (uint64, bool) {
		ident, ok := w.idents[pid]
		return ident.started, ok
	}
	attachPIDGroupUprobes = func(_ *ebpf.Collection, _ probes.ProbeGroup, _ string, pid uint32, _ *probes.AttachedFiles) []link.Link {
		w.full[pid]++
		return []link.Link{&fakeLink{}}
	}
	attachProcessScopedProbes = func(_ *ebpf.Collection, pid uint32) []link.Link {
		l := &fakeLink{}
		w.scoped[pid] = append(w.scoped[pid], l)
		return []link.Link{l}
	}
	t.Cleanup(func() {
		readProcessIdentity, attachPIDGroupUprobes, attachProcessScopedProbes, processStartTime = origIdent, origAttach, origScoped, origStart
	})
	w.tr = &Tracer{collection: &ebpf.Collection{}}
	w.tr.setCgroupPaths([]string{w.cgroupDir})
	return w
}

func (w *rescanWorld) setProcesses(idents map[uint32]processIdentity) {
	w.t.Helper()
	w.idents = idents
	pids := make([]uint32, 0, len(idents))
	for pid := range idents {
		pids = append(pids, pid)
	}
	slices.Sort(pids)
	var b strings.Builder
	for _, pid := range pids {
		fmt.Fprintf(&b, "%d\n", pid)
	}
	if err := os.WriteFile(filepath.Join(w.cgroupDir, "cgroup.procs"), []byte(b.String()), 0o600); err != nil {
		w.t.Fatal(err)
	}
}

func (w *rescanWorld) target(seeds ...uint32) {
	w.t.Helper()
	if err := w.tr.SetContainerTargets([]ContainerProbeTarget{{ID: rescanContainerID, PIDs: seeds}}); err != nil {
		w.t.Fatal(err)
	}
}

func (w *rescanWorld) set() *containerUprobeSet {
	return w.tr.containerUprobes[rescanContainerID]
}

func executableNo(n uint64) exeKey { return exeKey{dev: 1, ino: n} }

func TestASecondProcessOfAnAttachedBinaryGetsItsProcessScopedProbes(t *testing.T) {
	w := newRescanWorld(t, map[uint32]processIdentity{10: {100, executableNo(1)}, 11: {110, executableNo(1)}})
	w.target()
	if w.full[10] != len(containerUprobeGroups) || w.full[11] != 0 {
		t.Fatalf("full attaches %v, want every group through pid 10 only", w.full)
	}
	if len(w.scoped[11]) != 1 || len(w.scoped[10]) != 0 {
		t.Fatalf("scoped attaches %v, want pid 11 alone", w.scoped)
	}
	w.tr.rescanContainerProcesses()
	if len(w.scoped[11]) != 1 {
		t.Errorf("a rescan with nothing changed attached pid 11 again (%d)", len(w.scoped[11]))
	}
}

func TestAProcessThatExitsHasItsProcessScopedProbesDetached(t *testing.T) {
	w := newRescanWorld(t, map[uint32]processIdentity{10: {100, executableNo(1)}, 11: {110, executableNo(1)}})
	w.target()
	w.setProcesses(map[uint32]processIdentity{10: {100, executableNo(1)}})
	w.tr.rescanContainerProcesses()
	if w.scoped.closes(11) != 1 {
		t.Errorf("pid 11's process-scoped link closed %d times after it exited, want 1", w.scoped.closes(11))
	}
	if _, ok := w.set().scoped[11]; ok {
		t.Error("the exited process is still recorded")
	}
}

func TestARestartedProcessGetsItsProcessScopedProbesAgain(t *testing.T) {
	w := newRescanWorld(t, map[uint32]processIdentity{10: {100, executableNo(1)}, 11: {110, executableNo(1)}})
	w.target()
	w.setProcesses(map[uint32]processIdentity{10: {100, executableNo(1)}, 11: {999, executableNo(1)}})
	w.tr.rescanContainerProcesses()
	if len(w.scoped[11]) != 2 || w.scoped[11][0].closes.Load() != 1 || w.scoped[11][1].closes.Load() != 0 {
		t.Fatalf("pid 11 links %v, want the old process's detached and the new one's attached", w.scoped[11])
	}
}

func TestAProcessThatExecsInPlaceGetsTheNewBinarysProbes(t *testing.T) {
	w := newRescanWorld(t, map[uint32]processIdentity{10: {100, executableNo(1)}})
	w.target()
	w.setProcesses(map[uint32]processIdentity{10: {100, executableNo(2)}})
	w.tr.rescanContainerProcesses()
	if w.full[10] != 2*len(containerUprobeGroups) {
		t.Fatalf("pid 10 attached %d times, want every group again for the binary it exec'd", w.full[10])
	}
	if rep := w.set().reps[10]; rep.exe != executableNo(2) {
		t.Errorf("pid 10 recorded as %+v, want the new binary", rep)
	}
}

func TestABinaryStartedLaterInARunningContainerIsAttached(t *testing.T) {
	w := newRescanWorld(t, map[uint32]processIdentity{10: {100, executableNo(1)}})
	w.target()
	w.setProcesses(map[uint32]processIdentity{10: {100, executableNo(1)}, 12: {120, executableNo(3)}, 13: {130, executableNo(3)}})
	w.tr.rescanContainerProcesses()
	if w.full[12] != len(containerUprobeGroups) || w.full[13] != 0 || len(w.scoped[13]) != 1 {
		t.Fatalf("full %v scoped %v, want the new binary attached through pid 12 and pid 13 scoped", w.full, w.scoped)
	}
	if got := w.set().attachPIDs(); len(got) != 2 || got[0] != 10 || got[1] != 12 {
		t.Errorf("attachPIDs = %v, want [10 12] so a re-enabled group covers the new binary", got)
	}
}

func TestARescanStopsAddingBinariesAtTheCap(t *testing.T) {
	idents := map[uint32]processIdentity{}
	for i := uint32(0); i < maxDistinctBinariesPerContainer; i++ {
		idents[20+i] = processIdentity{uint64(i), executableNo(uint64(10 + i))}
	}
	w := newRescanWorld(t, idents)
	w.target()
	idents[99] = processIdentity{9, executableNo(99)}
	w.setProcesses(idents)
	w.tr.rescanContainerProcesses()
	if w.full[99] != 0 || len(w.scoped[99]) != 0 {
		t.Fatalf("pid 99 attached (full %d, scoped %d) past the %d-binary cap", w.full[99], len(w.scoped[99]), maxDistinctBinariesPerContainer)
	}
}

func TestProcessScopedProbesWaitWhileTLSIsDisabled(t *testing.T) {
	w := newRescanWorld(t, map[uint32]processIdentity{10: {100, executableNo(1)}, 11: {110, executableNo(1)}})
	w.tr.intentionallyDisabled = map[probes.ProbeGroup]struct{}{probes.GroupTLS: {}}
	w.target()
	if len(w.scoped[11]) != 0 {
		t.Fatal("process-scoped TLS probes attached while TLS is disabled")
	}
	delete(w.tr.intentionallyDisabled, probes.GroupTLS)
	w.tr.rescanContainerProcesses()
	if len(w.scoped[11]) != 1 {
		t.Fatal("process-scoped probes were not attached once TLS was enabled again")
	}
}

func TestDisablingTLSDetachesProcessScopedProbes(t *testing.T) {
	w := newRescanWorld(t, map[uint32]processIdentity{10: {100, executableNo(1)}, 11: {110, executableNo(1)}})
	w.target()
	w.tr.DisableProbeGroup(probes.GroupTLS)
	if w.scoped.closes(11) != 1 || len(w.set().scoped) != 0 {
		t.Fatalf("closes %d, recorded %v; want pid 11's process-scoped link detached with TLS", w.scoped.closes(11), w.set().scoped)
	}
}

func TestStoppingClosesProcessScopedProbes(t *testing.T) {
	l := &fakeLink{}
	set := &containerUprobeSet{scoped: map[uint32]scopedProcess{11: {links: []link.Link{l}}}}
	if got := set.allLinks(); len(got) != 1 || got[0] != l {
		t.Fatalf("allLinks = %v, want the process-scoped link included", got)
	}
}

func TestARescanLeavesAContainerItCannotListAlone(t *testing.T) {
	w := newRescanWorld(t, map[uint32]processIdentity{10: {100, executableNo(1)}, 11: {110, executableNo(1)}})
	w.target()
	w.tr.setCgroupPaths(nil)
	w.tr.rescanContainerProcesses()
	if w.scoped.closes(11) != 0 {
		t.Fatal("a container whose processes could not be listed lost its process-scoped probes")
	}
}

func TestProcessScopedProbesOfAReusedPidAreDetached(t *testing.T) {
	w := newRescanWorld(t, map[uint32]processIdentity{10: {100, executableNo(1)}})
	w.target()
	set := w.set()
	w.idents[11] = processIdentity{999, executableNo(1)}
	w.tr.containerAttachMu.Lock()
	w.tr.attachScopedProcess(rescanContainerID, set, 11, processIdentity{110, executableNo(1)}, processStarts{11: 110})
	w.tr.containerAttachMu.Unlock()
	if w.scoped.closes(11) != 1 {
		t.Fatal("links attached through a reused pid were kept")
	}
	if _, ok := set.scoped[11]; ok {
		t.Error("the reused pid was recorded")
	}
}

func TestRescannedLinksAreClosedWhenTheTracerStopsOrTheContainerLeaves(t *testing.T) {
	w := newRescanWorld(t, map[uint32]processIdentity{10: {100, executableNo(1)}})
	w.target()
	set := w.set()
	w.idents[11] = processIdentity{110, executableNo(1)}
	w.idents[12] = processIdentity{120, executableNo(2)}
	w.tr.probesClosed = true
	w.tr.attachScopedProcess(rescanContainerID, set, 11, w.idents[11], processStarts{11: 110})
	w.tr.attachRescannedBinaries(rescanContainerID, set, []uint32{12}, w.idents, processStarts{12: 120})
	if w.scoped.closes(11) != 1 {
		t.Error("a process-scoped link attached after stop was kept")
	}
	w.tr.probesClosed = false
	w.tr.rescanContainer("no-such-container")
	if _, ok := set.reps[12]; ok {
		t.Error("a binary attached after stop was recorded")
	}
	w.tr.intentionallyDisabled = map[probes.ProbeGroup]struct{}{probes.GroupTLS: {}}
	w.tr.attachScopedProcess(rescanContainerID, set, 11, w.idents[11], processStarts{11: 110})
	if w.scoped.closes(11) != 2 {
		t.Error("a process-scoped link attached while TLS was being disabled was kept")
	}
}

func TestTheRescanLoopRunsUntilItsContextEnds(t *testing.T) {
	w := newRescanWorld(t, map[uint32]processIdentity{10: {100, executableNo(1)}})
	w.target()
	var rescans atomic.Int32
	orig := readProcessIdentity
	readProcessIdentity = func(pid uint32) (processIdentity, bool) {
		rescans.Add(1)
		return orig(pid)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.tr.rescanContainerProcessesLoop(ctx, time.Millisecond)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for rescans.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if rescans.Load() == 0 {
		t.Fatal("the loop never rescanned")
	}
}

func TestReadProcessIdentityNamesTheExecutable(t *testing.T) {
	fakeContainerProc(t, rescanContainerID, []uint32{40, 41}, map[uint32]string{40: "server"})
	orig := processStartTime
	t.Cleanup(func() { processStartTime = orig })
	processStartTime = func(pid uint32) (uint64, bool) { return 7, pid != 42 }
	ident, ok := readProcessIdentity(40)
	if !ok || ident.started != 7 || ident.exe.ino == 0 {
		t.Fatalf("readProcessIdentity(40) = %+v, %v", ident, ok)
	}
	if _, ok := readProcessIdentity(41); ok {
		t.Error("a process without an executable got an identity")
	}
	if _, ok := readProcessIdentity(42); ok {
		t.Error("a process without a start time got an identity")
	}
}

func TestPidsForContainerNeverReadsAContainerSharingTheShortPrefix(t *testing.T) {
	const target = "0123456789abffff0123456789abcdef0123456789abcdef0123456789abcdef"
	const sibling = "0123456789ab00000123456789abcdef0123456789abcdef0123456789abcdef"
	siblingDir := fakeContainerProc(t, sibling, []uint32{501}, map[uint32]string{})
	tr := &Tracer{}
	tr.setCgroupPaths([]string{siblingDir})
	if got := tr.containerProcesses(target); got != nil {
		t.Fatalf("containerProcesses = %v, the processes of another container", got)
	}
}

func TestARescanAfterStopAttachesNothing(t *testing.T) {
	w := newRescanWorld(t, map[uint32]processIdentity{10: {100, executableNo(1)}})
	w.target()
	w.setProcesses(map[uint32]processIdentity{10: {100, executableNo(1)}, 11: {110, executableNo(1)}})
	w.tr.probesClosed = true
	w.tr.rescanContainer(rescanContainerID)
	if len(w.scoped[11]) != 0 {
		t.Fatal("a rescan after stop attached process-scoped probes")
	}
}

func TestRecordingARepresentativeStartsItsRecords(t *testing.T) {
	set := &containerUprobeSet{}
	set.recordRepresentative(10, processIdentity{100, executableNo(1)})
	if _, ok := set.binaries[executableNo(1)]; !ok || set.reps[10].started != 100 {
		t.Fatalf("set = %+v, want pid 10 and its binary recorded", set)
	}
	if _, ok := set.seen[10]; !ok {
		t.Error("the representative was not marked seen, so a target pass would attach it again")
	}
}
