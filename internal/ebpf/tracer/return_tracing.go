package tracer

import (
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/ebpf/probes"
	"github.com/gma1k/podtrace/internal/logger"
)

// funcRetAvailable reports whether the kernel lets an fexit program read the
// return value with bpf_get_func_ret, which arrived in 5.17.
var funcRetAvailable = sync.OnceValue(func() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:       ebpf.Tracing,
		AttachType: ebpf.AttachTraceFExit,
		AttachTo:   "bpf_init",
		License:    "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -8),
			asm.FnGetFuncRet.Call(),
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		return false
	}
	_ = prog.Close()
	return true
})

// pruneReturnTracingIfUnsupported drops the return probes' fexit builds the
// kernel cannot load, which would otherwise fail the whole collection.
func pruneReturnTracingIfUnsupported(spec *ebpf.CollectionSpec, btfFromFile bool) {
	reason := ""
	var kernel *btf.Spec
	switch {
	case btfFromFile:
		reason = "BTF is supplied from a file"
	case !tracingProgramsAvailable():
		reason = "the kernel lacks the tracing program type"
	case !funcRetAvailable():
		reason = "the kernel lacks bpf_get_func_ret (needs 5.17)"
	default:
		k, err := loadKernelBTF()
		if err != nil {
			reason = "the kernel's BTF cannot be read: " + err.Error()
		}
		kernel = k
	}

	var dropped []string
	for _, name := range probes.ReturnTracingPrograms() {
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
	if reason == "" {
		reason = "their kernel functions are not in the kernel's BTF"
	}
	logger.Info("Return probes will use kretprobes rather than fexit, so they can drop returns on a busy node",
		zap.String("reason", reason), zap.String("programs", strings.Join(dropped, ",")))
}
