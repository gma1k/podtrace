package tracer

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"github.com/gma1k/podtrace/internal/ebpf/probes"
)

func kernelWith(t *testing.T, funcs ...string) *btf.Spec {
	t.Helper()
	b, err := btf.NewBuilder(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	proto := &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}}
	for _, f := range funcs {
		if _, err := b.Add(&btf.Func{Name: f, Type: proto, Linkage: btf.GlobalFunc}); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := b.Marshal(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func fsSpec() *ebpf.CollectionSpec {
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{"kprobe_vfs_read": {}},
		Maps:     map[string]*ebpf.MapSpec{fsTaskInflightMapName: {}, "fs_inflight": {}},
	}
	for _, name := range probes.FSTracingPrograms() {
		target := "vfs_read"
		if name == "fentry_vfs_write" || name == "fexit_vfs_write" {
			target = "vfs_write"
		}
		spec.Programs[name] = &ebpf.ProgramSpec{AttachTo: target}
	}
	return spec
}

func withKernel(t *testing.T, tracing bool, kernel *btf.Spec, err error) {
	t.Helper()
	withKernelStorage(t, tracing, true, kernel, err)
}

func withKernelStorage(t *testing.T, tracing, taskStorage bool, kernel *btf.Spec, err error) {
	t.Helper()
	origTracing, origStorage, origBTF := tracingProgramsAvailable, taskStorageAvailable, loadKernelBTF
	t.Cleanup(func() {
		tracingProgramsAvailable, taskStorageAvailable, loadKernelBTF = origTracing, origStorage, origBTF
	})
	tracingProgramsAvailable = func() bool { return tracing }
	taskStorageAvailable = func() bool { return taskStorage }
	loadKernelBTF = func() (*btf.Spec, error) { return kernel, err }
}

func tracingLeft(spec *ebpf.CollectionSpec) int { return tracingProgramsLeft(spec) }

func TestTheFentryBuildIsKeptWhereTheKernelCanLoadIt(t *testing.T) {
	withKernel(t, true, kernelWith(t, "vfs_read", "vfs_write"), nil)
	spec := fsSpec()
	pruneFSTracingIfUnsupported(spec, false)
	if got := tracingLeft(spec); got != len(probes.FSTracingPrograms()) {
		t.Errorf("%d fentry/fexit programs left, want all of them", got)
	}
}

func TestTheFentryBuildIsDroppedWhereTheKernelCannotLoadIt(t *testing.T) {
	for name, c := range map[string]struct {
		fromFile bool
		tracing  bool
		kernel   *btf.Spec
		err      error
	}{
		"btf from a file":       {fromFile: true, tracing: true},
		"no tracing programs":   {tracing: false},
		"kernel btf unreadable": {tracing: true, err: errors.New("no /sys/kernel/btf/vmlinux")},
	} {
		t.Run(name, func(t *testing.T) {
			kernel := c.kernel
			if kernel == nil && c.err == nil {
				kernel = kernelWith(t, "vfs_read", "vfs_write")
			}
			withKernel(t, c.tracing, kernel, c.err)
			spec := fsSpec()
			pruneFSTracingIfUnsupported(spec, c.fromFile)
			if got := tracingLeft(spec); got != 0 {
				t.Errorf("%d fentry/fexit programs left; one that cannot load fails the whole collection", got)
			}
			if _, ok := spec.Programs["kprobe_vfs_read"]; !ok {
				t.Error("the kprobe build was dropped too")
			}
			if _, ok := spec.Maps[fsTaskInflightMapName]; ok {
				t.Error("the task-storage map was kept; a kernel without it fails the whole collection")
			}
			if _, ok := spec.Maps["fs_inflight"]; !ok {
				t.Error("the kprobe build's map was dropped")
			}
		})
	}
}

func TestOnlyTheProgramsWhoseFunctionIsMissingAreDropped(t *testing.T) {
	withKernel(t, true, kernelWith(t, "vfs_read"), nil)
	spec := fsSpec()
	pruneFSTracingIfUnsupported(spec, false)
	if _, ok := spec.Programs["fentry_vfs_read"]; !ok {
		t.Error("a program whose function exists was dropped")
	}
	if _, ok := spec.Programs["fexit_vfs_write"]; ok {
		t.Error("a program whose function is not in the kernel's BTF was kept")
	}
}

func TestPruningASpecWithoutTheFentryBuildChangesNothing(t *testing.T) {
	withKernel(t, false, nil, nil)
	spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{"kprobe_vfs_read": {}}}
	pruneFSTracingIfUnsupported(spec, false)
	if len(spec.Programs) != 1 {
		t.Errorf("programs = %v", spec.Programs)
	}
}

func TestTheFastFilesystemCountsNeedALoadedObject(t *testing.T) {
	var none *Tracer
	if err := none.CountFastFilesystemOps(); err == nil {
		t.Error("a nil tracer switched counting on")
	}
	if rows, err := none.DrainFastFilesystemOps(); rows != nil || err != nil {
		t.Errorf("a nil tracer drained %v, %v", rows, err)
	}
	bare := &Tracer{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}
	if err := bare.CountFastFilesystemOps(); err == nil {
		t.Error("an object without the switch map switched counting on")
	}
	if _, err := bare.DrainFastFilesystemOps(); err == nil {
		t.Error("an object without the counts map was drained")
	}
}

func TestAKernelWithoutTaskStorageUsesKprobes(t *testing.T) {
	withKernelStorage(t, true, false, kernelWith(t, "vfs_read", "vfs_write"), nil)
	spec := fsSpec()
	pruneFSTracingIfUnsupported(spec, false)
	if tracingLeft(spec) != 0 {
		t.Error("the fentry build was kept on a kernel without task storage")
	}
	if _, ok := spec.Maps[fsTaskInflightMapName]; ok {
		t.Error("the task-storage map was kept")
	}
}

func TestTheTaskStorageMapStaysWhileAFentryProgramUsesIt(t *testing.T) {
	withKernel(t, true, kernelWith(t, "vfs_read"), nil)
	spec := fsSpec()
	pruneFSTracingIfUnsupported(spec, false)
	if _, ok := spec.Maps[fsTaskInflightMapName]; !ok {
		t.Error("the task-storage map was dropped while fentry_vfs_read still needs it")
	}
}
