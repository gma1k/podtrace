package tracer

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/ebpf/probes"
	"github.com/gma1k/podtrace/internal/logger"
)

var (
	tracingProgramsAvailable = func() bool {
		return features.HaveProgramType(ebpf.Tracing) == nil
	}
	taskStorageAvailable = func() bool {
		return features.HaveMapType(ebpf.TaskStorage) == nil
	}
	loadKernelBTF = btf.LoadKernelSpec
)

// pruneFSTracingIfUnsupported drops the fentry/fexit filesystem programs the
// kernel cannot load, which would otherwise fail the whole collection.
func pruneFSTracingIfUnsupported(spec *ebpf.CollectionSpec, btfFromFile bool) {
	reason := ""
	var kernel *btf.Spec
	switch {
	case btfFromFile:
		reason = "BTF is supplied from a file"
	case !tracingProgramsAvailable():
		reason = "the kernel lacks the tracing program type"
	case !taskStorageAvailable():
		reason = "the kernel lacks task-local storage (needs 5.11)"
	default:
		k, err := loadKernelBTF()
		if err != nil {
			reason = "the kernel's BTF cannot be read: " + err.Error()
		}
		kernel = k
	}

	var dropped []string
	for _, name := range probes.FSTracingPrograms() {
		prog, ok := spec.Programs[name]
		if !ok {
			continue
		}
		if reason == "" {
			var fn *btf.Func
			if err := kernel.TypeByName(prog.AttachTo, &fn); err == nil {
				continue
			}
		}
		delete(spec.Programs, name)
		dropped = append(dropped, name)
	}
	if len(dropped) == 0 {
		return
	}
	if tracingProgramsLeft(spec) == 0 {
		delete(spec.Maps, fsTaskInflightMapName)
	}
	if reason == "" {
		reason = "their kernel functions are not in the kernel's BTF"
	}
	logger.Info("Filesystem probes will use kprobes rather than fentry/fexit",
		zap.String("reason", reason), zap.String("programs", strings.Join(dropped, ",")))
}

// tracingProgramsLeft counts the fentry/fexit filesystem programs a spec
// still holds.
func tracingProgramsLeft(spec *ebpf.CollectionSpec) int {
	n := 0
	for _, name := range probes.FSTracingPrograms() {
		if _, ok := spec.Programs[name]; ok {
			n++
		}
	}
	return n
}

const (
	fsTaskInflightMapName   = "fs_task_inflight"
	fsFastOpsMapName        = "fs_fast_ops"
	fsFastOpsEnabledMapName = "fs_fast_ops_enabled"
)

// CountFastFilesystemOps has the kernel count the filesystem operations too
// fast to become events, for a run without kernel aggregation, so a report
// counts every operation rather than only the slow ones.
func (t *Tracer) CountFastFilesystemOps() error {
	if t == nil || t.collection == nil {
		return errors.New("fast filesystem counts: no BPF collection loaded")
	}
	m := t.collection.Maps[fsFastOpsEnabledMapName]
	if m == nil {
		return errors.New("fast filesystem counts: the BPF object has no " + fsFastOpsEnabledMapName + " map")
	}
	key, on := uint32(0), uint32(1)
	if err := m.Update(&key, &on, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("fast filesystem counts: %w", err)
	}
	return nil
}

// DrainFastFilesystemOps reads and clears what CountFastFilesystemOps counted.
func (t *Tracer) DrainFastFilesystemOps() ([]kernelagg.Row, error) {
	if t == nil || t.collection == nil {
		return nil, nil
	}
	return kernelagg.Drain(t.collection.Maps[fsFastOpsMapName])
}
