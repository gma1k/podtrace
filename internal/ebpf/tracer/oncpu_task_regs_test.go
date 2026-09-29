package tracer

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/gma1k/podtrace/internal/ebpf/oncpu"
)

func withTaskPtRegs(t *testing.T, available bool) {
	t.Helper()
	orig := taskPtRegsAvailable
	taskPtRegsAvailable = func() bool { return available }
	t.Cleanup(func() { taskPtRegsAvailable = orig })
}

func samplerSpec() *ebpf.CollectionSpec {
	return &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{
		oncpu.ProgramName:         {Name: oncpu.ProgramName},
		oncpu.TaskRegsProgramName: {Name: oncpu.TaskRegsProgramName},
	}}
}

func TestTheTaskRegsSamplerIsDroppedWhereTheKernelLacksItsHelper(t *testing.T) {
	withTaskPtRegs(t, false)
	spec := samplerSpec()
	pruneOnCPUTaskRegsIfUnsupported(spec)
	if _, ok := spec.Programs[oncpu.TaskRegsProgramName]; ok {
		t.Error("the task-regs build was kept on a kernel that cannot load it")
	}
	if _, ok := spec.Programs[oncpu.ProgramName]; !ok {
		t.Error("the plain build was dropped too")
	}
}

func TestTheTaskRegsSamplerIsKeptWhereTheKernelHasItsHelper(t *testing.T) {
	withTaskPtRegs(t, true)
	spec := samplerSpec()
	pruneOnCPUTaskRegsIfUnsupported(spec)
	if len(spec.Programs) != 2 {
		t.Errorf("programs = %v", spec.Programs)
	}

	called := false
	taskPtRegsAvailable = func() bool { called = true; return false }
	pruneOnCPUTaskRegsIfUnsupported(&ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{}})
	if called {
		t.Error("the kernel was probed for an object without the task-regs build")
	}
}

func TestTheSamplerAttachesTheTaskRegsBuildWhenItLoaded(t *testing.T) {
	plain, taskRegs := &ebpf.Program{}, &ebpf.Program{}
	var got *ebpf.Program
	orig := attachOnCPU
	attachOnCPU = func(p *ebpf.Program) (*oncpu.Sampler, error) { got = p; return nil, errTestAttach }
	t.Cleanup(func() { attachOnCPU = orig })
	enabled := map[string]*ebpf.Map{oncpu.EnabledMapName: {}}

	tr := &Tracer{collection: &ebpf.Collection{Maps: enabled, Programs: map[string]*ebpf.Program{
		oncpu.ProgramName: plain, oncpu.TaskRegsProgramName: taskRegs}}}
	if _, err := tr.StartOnCPUSampler(); !errors.Is(err, errTestAttach) || got != taskRegs {
		t.Errorf("attached %p, want the task-regs build %p", got, taskRegs)
	}

	tr = &Tracer{collection: &ebpf.Collection{Maps: enabled, Programs: map[string]*ebpf.Program{oncpu.ProgramName: plain}}}
	_, _ = tr.StartOnCPUSampler()
	if got != plain {
		t.Errorf("attached %p, want the plain build %p when the task-regs one was pruned", got, plain)
	}
}

func TestTheTaskRegsProbeAsksTheKernel(t *testing.T) {
	_ = taskPtRegsAvailable()
}
