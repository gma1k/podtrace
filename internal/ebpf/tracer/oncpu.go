package tracer

import (
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"

	"github.com/gma1k/podtrace/internal/ebpf/oncpu"
	"github.com/gma1k/podtrace/internal/logger"
)

var attachOnCPU = oncpu.Attach

// StartOnCPUSampler attaches the fixed-rate on-CPU sampler to every CPU and
// switches the request-attribution hooks on, returning how many CPUs it runs
// on. Calling it again while it runs is a no-op.
func (t *Tracer) StartOnCPUSampler() (int, error) {
	if t == nil || t.collection == nil {
		return 0, errors.New("on-CPU sampler: no BPF collection loaded")
	}
	t.onCPUMu.Lock()
	defer t.onCPUMu.Unlock()
	if t.onCPUSampler != nil {
		return t.onCPUSampler.CPUs(), nil
	}
	enabled := t.collection.Maps[oncpu.EnabledMapName]
	if enabled == nil {
		return 0, errors.New("on-CPU sampler: the BPF object has no " + oncpu.EnabledMapName + " map")
	}
	prog := t.collection.Programs[oncpu.TaskRegsProgramName]
	if prog == nil {
		prog = t.collection.Programs[oncpu.ProgramName]
	}
	sampler, err := attachOnCPU(prog)
	if err != nil {
		return 0, err
	}
	if err := oncpu.SetEnabled(enabled, true); err != nil {
		_ = sampler.Close()
		return 0, err
	}
	t.onCPUSampler = sampler
	return sampler.CPUs(), nil
}

// DrainOnCPUSamples reads and clears what the sampler counted since the
// previous drain.
func (t *Tracer) DrainOnCPUSamples() (oncpu.Drained, error) {
	if t == nil || t.collection == nil {
		return oncpu.Drained{}, nil
	}
	maps, err := oncpu.MapsFrom(t.collection.Maps)
	if err != nil {
		return oncpu.Drained{}, err
	}
	return oncpu.Drain(maps)
}

// stopOnCPUSampler detaches the sampler, leaving the hooks switched off.
func (t *Tracer) stopOnCPUSampler() {
	t.onCPUMu.Lock()
	defer t.onCPUMu.Unlock()
	if t.onCPUSampler == nil {
		return
	}
	if t.collection != nil {
		if enabled := t.collection.Maps[oncpu.EnabledMapName]; enabled != nil {
			_ = oncpu.SetEnabled(enabled, false)
		}
	}
	_ = t.onCPUSampler.Close()
	t.onCPUSampler = nil
}

var taskPtRegsAvailable = func() bool {
	return features.HaveProgramHelper(ebpf.PerfEvent, asm.FnTaskPtRegs) == nil
}

// pruneOnCPUTaskRegsIfUnsupported drops the task-regs sampler build on a
// kernel without bpf_task_pt_regs, which would otherwise fail the whole
// collection. The plain build then runs, and a Go sample taken inside the
// kernel is not charged to its request.
func pruneOnCPUTaskRegsIfUnsupported(spec *ebpf.CollectionSpec) {
	if _, ok := spec.Programs[oncpu.TaskRegsProgramName]; !ok || taskPtRegsAvailable() {
		return
	}
	delete(spec.Programs, oncpu.TaskRegsProgramName)
	logger.Info("Kernel lacks bpf_task_pt_regs (needs 5.15+); the on-CPU sampler will not charge " +
		"a Go request for CPU it spends inside the kernel")
}
