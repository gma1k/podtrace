package tracer

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"github.com/gma1k/podtrace/internal/ebpf/probes"
)

func returnSpec() *ebpf.CollectionSpec {
	spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{"kretprobe_tcp_recvmsg": {AttachTo: "tcp_recvmsg"}}}
	targets := map[string]string{
		"fexit_tcp_recvmsg": "tcp_recvmsg", "fexit_tcp_sendmsg": "tcp_sendmsg",
		"fexit_udp_recvmsg": "udp_recvmsg", "fexit_udp_sendmsg": "udp_sendmsg",
		"fexit_http_tcp_recvmsg": "tcp_recvmsg", "fexit_h2_tcp_recvmsg": "tcp_recvmsg",
		"fexit_h2_tcp_sendmsg": "tcp_sendmsg", "fexit_unix_stream_recvmsg": "unix_stream_recvmsg",
		"fexit_do_futex": "do_futex",
	}
	for _, name := range probes.ReturnTracingPrograms() {
		spec.Programs[name] = &ebpf.ProgramSpec{AttachTo: targets[name]}
	}
	return spec
}

func withFuncRet(t *testing.T, available bool) {
	t.Helper()
	orig := funcRetAvailable
	t.Cleanup(func() { funcRetAvailable = orig })
	funcRetAvailable = func() bool { return available }
}

func fexitLeft(spec *ebpf.CollectionSpec) []string {
	var out []string
	for _, name := range probes.ReturnTracingPrograms() {
		if _, ok := spec.Programs[name]; ok {
			out = append(out, name)
		}
	}
	return out
}

var allReturnTargets = []string{"tcp_recvmsg", "tcp_sendmsg", "udp_recvmsg", "udp_sendmsg", "unix_stream_recvmsg", "do_futex"}

func TestTheFexitReturnsAreKeptWhereTheKernelCanLoadThem(t *testing.T) {
	withKernel(t, true, kernelWith(t, allReturnTargets...), nil)
	withFuncRet(t, true)
	spec := returnSpec()
	pruneReturnTracingIfUnsupported(spec, false)
	if got := fexitLeft(spec); len(got) != len(probes.ReturnTracingPrograms()) {
		t.Errorf("%d fexit returns left, want all", len(got))
	}
	if _, ok := spec.Programs["kretprobe_tcp_recvmsg"]; !ok {
		t.Error("the kretprobe was dropped; it is the fallback where an fexit cannot attach")
	}
}

func TestTheFexitReturnsAreDroppedWhereTheKernelCannotLoadThem(t *testing.T) {
	for name, c := range map[string]struct {
		fromFile, tracing, funcRet bool
		err                        error
	}{
		"btf from a file":       {fromFile: true, tracing: true, funcRet: true},
		"no tracing programs":   {tracing: false, funcRet: true},
		"no bpf_get_func_ret":   {tracing: true, funcRet: false},
		"kernel btf unreadable": {tracing: true, funcRet: true, err: errors.New("no /sys/kernel/btf/vmlinux")},
	} {
		t.Run(name, func(t *testing.T) {
			var kernel *btf.Spec
			if c.err == nil {
				kernel = kernelWith(t, allReturnTargets...)
			}
			withKernel(t, c.tracing, kernel, c.err)
			withFuncRet(t, c.funcRet)
			spec := returnSpec()
			pruneReturnTracingIfUnsupported(spec, c.fromFile)
			if got := fexitLeft(spec); len(got) != 0 {
				t.Errorf("left %v; loading them would fail the whole collection", got)
			}
		})
	}
}

func TestOnlyTheReturnWhoseFunctionIsMissingIsDropped(t *testing.T) {
	withKernel(t, true, kernelWith(t, "tcp_recvmsg", "tcp_sendmsg", "udp_recvmsg", "udp_sendmsg", "unix_stream_recvmsg"), nil)
	withFuncRet(t, true)
	spec := returnSpec()
	pruneReturnTracingIfUnsupported(spec, false)
	if _, ok := spec.Programs["fexit_do_futex"]; ok {
		t.Error("fexit_do_futex kept though the kernel has no do_futex")
	}
	if got := len(fexitLeft(spec)); got != len(probes.ReturnTracingPrograms())-1 {
		t.Errorf("%d left, want every other one", got)
	}
}

func TestTheFuncRetProbeAnswersWithoutPanicking(t *testing.T) {
	_ = funcRetAvailable()
}

func TestAnObjectWithoutTheFexitBuildsIsLeftAlone(t *testing.T) {
	withKernel(t, true, kernelWith(t, allReturnTargets...), nil)
	withFuncRet(t, true)
	spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{"kretprobe_tcp_recvmsg": {AttachTo: "tcp_recvmsg"}}}
	pruneReturnTracingIfUnsupported(spec, false)
	if len(spec.Programs) != 1 {
		t.Errorf("programs %v, want the kretprobe untouched", spec.Programs)
	}
}
