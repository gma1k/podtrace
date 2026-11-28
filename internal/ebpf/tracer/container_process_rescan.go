package tracer

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/probes"
	"github.com/gma1k/podtrace/internal/logger"
)

// SetContainerTargets runs only when the node's set of target cgroups changes,
// and attaches through one process per executable.
const containerProcessRescanInterval = 10 * time.Second

// processIdentity tells a process apart from an earlier one that held its pid,
// and from the binary the same pid ran before an exec.
type processIdentity struct {
	started uint64
	exe     exeKey
}

// readProcessIdentity reads pid's identity, failing for a process that has
// exited. It is a variable so tests can stand in for /proc.
var readProcessIdentity = func(pid uint32) (processIdentity, bool) {
	started, ok := processStartTime(pid)
	if !ok {
		return processIdentity{}, false
	}
	sys, err := statRecord(filepath.Join(config.ProcBasePath, fmt.Sprint(pid), "exe"))
	if err != nil {
		return processIdentity{}, false
	}
	return processIdentity{started: started, exe: exeKey{dev: uint64(sys.Dev), ino: sys.Ino}}, true
}

// scopedProcess holds the uprobes attached for one more process of an
// attached binary. They cover only that process.
type scopedProcess struct {
	ident processIdentity
	links []link.Link
}

// attachProcessScopedProbes is the probes call behind a scoped attach, a
// variable so tests can stand in for it.
var attachProcessScopedProbes = probes.AttachProcessScopedProbes

// rescanContainerProcessesLoop rescans every targeted container until ctx ends.
func (t *Tracer) rescanContainerProcessesLoop(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.rescanContainerProcesses()
		}
	}
}

// rescanContainerProcesses brings every targeted container's uprobes up to
// date with the processes it runs now.
func (t *Tracer) rescanContainerProcesses() {
	t.containerAttachMu.Lock()
	defer t.containerAttachMu.Unlock()
	t.probeGroupsMu.Lock()
	ids := make([]string, 0, len(t.containerUprobes))
	for id := range t.containerUprobes {
		ids = append(ids, id)
	}
	t.probeGroupsMu.Unlock()
	slices.Sort(ids)
	for _, id := range ids {
		t.rescanContainer(id)
	}
}

// rescanPlan is what one rescan of a container has to attach.
type rescanPlan struct {
	full    []uint32
	scoped  []uint32
	closing []link.Link
}

// rescanContainer reconciles one container: a process running a binary no
// attach covered yet gets the binary's probes, every other new process gets
// the process-scoped probes, and those of processes that exited or exec'd are
// detached. The caller holds containerAttachMu.
func (t *Tracer) rescanContainer(id string) {
	procs := t.containerProcesses(id)
	if len(procs) == 0 {
		return
	}
	idents := make(map[uint32]processIdentity, len(procs))
	for _, pid := range procs {
		if ident, ok := readProcessIdentity(pid); ok {
			idents[pid] = ident
		}
	}

	t.probeGroupsMu.Lock()
	set := t.containerUprobes[id]
	if set == nil || t.probesClosed {
		t.probeGroupsMu.Unlock()
		return
	}
	plan := set.planRescan(idents)
	_, scopedDisabled := t.intentionallyDisabled[probes.GroupTLS]
	t.probeGroupsMu.Unlock()
	closeLinks(plan.closing)

	starts := make(processStarts, len(idents))
	for pid, ident := range idents {
		starts[pid] = ident.started
	}
	if len(plan.full) > 0 {
		t.attachRescannedBinaries(id, set, plan.full, idents, starts)
	}
	if scopedDisabled {
		return
	}
	for _, pid := range plan.scoped {
		t.attachScopedProcess(id, set, pid, idents[pid], starts)
	}
}

// planRescan compares the container's processes now with what the set has
// attached. The caller holds probeGroupsMu.
func (s *containerUprobeSet) planRescan(idents map[uint32]processIdentity) rescanPlan {
	var plan rescanPlan
	for pid, sp := range s.scoped {
		if cur, ok := idents[pid]; !ok || cur != sp.ident {
			plan.closing = append(plan.closing, sp.links...)
			delete(s.scoped, pid)
		}
	}
	for pid, rep := range s.reps {
		if cur, ok := idents[pid]; !ok || cur != rep {
			delete(s.reps, pid)
		}
	}
	pids := make([]uint32, 0, len(idents))
	for pid := range idents {
		pids = append(pids, pid)
	}
	slices.Sort(pids)
	adding := map[exeKey]struct{}{}
	for _, pid := range pids {
		ident := idents[pid]
		if _, rep := s.reps[pid]; rep {
			continue
		}
		if _, done := s.scoped[pid]; done {
			continue
		}
		_, covered := s.binaries[ident.exe]
		_, queued := adding[ident.exe]
		switch {
		case covered || queued:
			plan.scoped = append(plan.scoped, pid)
		case len(s.binaries)+len(adding) < maxDistinctBinariesPerContainer:
			adding[ident.exe] = struct{}{}
			plan.full = append(plan.full, pid)
		}
	}
	return plan
}

// attachRescannedBinaries attaches every group for processes running a binary
// the container's earlier attaches did not cover.
func (t *Tracer) attachRescannedBinaries(id string, set *containerUprobeSet, pids []uint32,
	idents map[uint32]processIdentity, starts processStarts) {
	links := t.attachContainerUprobes(id, pids, set, starts)
	t.probeGroupsMu.Lock()
	defer t.probeGroupsMu.Unlock()
	if t.probesClosed || t.containerUprobes[id] != set {
		closeLinks((&containerUprobeSet{links: links}).allLinks())
		return
	}
	for g, ls := range links {
		set.links[g] = append(set.links[g], ls...)
	}
	for _, pid := range pids {
		set.recordRepresentative(pid, idents[pid])
	}
	logger.Info("Uprobes attached for a binary started in a running container",
		zap.String("container_id", id), zap.Uint32s("pids", pids))
}

// attachScopedProcess attaches the process-scoped uprobes for one more process
// of an attached binary. A process that has none is recorded too, so it is not
// looked at again while it runs.
func (t *Tracer) attachScopedProcess(id string, set *containerUprobeSet, pid uint32, ident processIdentity, starts processStarts) {
	ls := attachProcessScopedProbes(t.collection, pid)
	if !starts.sameProcess(pid) {
		closeLinks(ls)
		return
	}
	t.probeGroupsMu.Lock()
	defer t.probeGroupsMu.Unlock()
	if t.probesClosed || t.containerUprobes[id] != set {
		closeLinks(ls)
		return
	}
	if _, disabled := t.intentionallyDisabled[probes.GroupTLS]; disabled {
		closeLinks(ls)
		return
	}
	set.scoped[pid] = scopedProcess{ident: ident, links: ls}
	if len(ls) > 0 {
		logger.Debug("Process-scoped uprobes attached",
			zap.String("container_id", id), zap.Uint32("pid", pid), zap.Int("links", len(ls)))
	}
}

// recordRepresentative records that pid's attach covered its binary. The
// caller holds probeGroupsMu.
func (s *containerUprobeSet) recordRepresentative(pid uint32, ident processIdentity) {
	if s.reps == nil {
		s.reps = map[uint32]processIdentity{}
	}
	if s.binaries == nil {
		s.binaries = map[exeKey]struct{}{}
	}
	s.reps[pid] = ident
	s.binaries[ident.exe] = struct{}{}
	if s.seen == nil {
		s.seen = map[uint32]struct{}{}
	}
	s.seen[pid] = struct{}{}
}

// attachPIDs returns the pids a re-enabled group reattaches through: the
// enumerated ones and those a rescan attached a binary through.
func (s *containerUprobeSet) attachPIDs() []uint32 {
	pids := slices.Clone(s.pids)
	for pid := range s.reps {
		if !slices.Contains(pids, pid) {
			pids = append(pids, pid)
		}
	}
	slices.Sort(pids)
	return pids
}

// dropScopedLinks detaches every process-scoped uprobe of the set and forgets
// the processes, so a later rescan attaches them again. The caller holds
// probeGroupsMu.
func (s *containerUprobeSet) dropScopedLinks() []link.Link {
	var out []link.Link
	for _, sp := range s.scoped {
		out = append(out, sp.links...)
	}
	s.scoped = map[uint32]scopedProcess{}
	return out
}
