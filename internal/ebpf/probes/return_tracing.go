package probes

import (
	"sort"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"

	"github.com/gma1k/podtrace/internal/logger"
)

// Return probes on functions a task can wait in.
//
// A kretprobe keeps one instance per task inside the function, from a pool
// of about twice the CPU count.
var returnTracing = map[string]string{
	"kretprobe_tcp_recvmsg":         "fexit_tcp_recvmsg",
	"kretprobe_tcp_sendmsg":         "fexit_tcp_sendmsg",
	"kretprobe_udp_recvmsg":         "fexit_udp_recvmsg",
	"kretprobe_udp_sendmsg":         "fexit_udp_sendmsg",
	"kretprobe_http_tcp_recvmsg":    "fexit_http_tcp_recvmsg",
	"kretprobe_h2_tcp_recvmsg":      "fexit_h2_tcp_recvmsg",
	"kretprobe_h2_tcp_sendmsg":      "fexit_h2_tcp_sendmsg",
	"kretprobe_unix_stream_recvmsg": "fexit_unix_stream_recvmsg",
	"kretprobe_do_futex":            "fexit_do_futex",
}

// ReturnTracingPrograms names the fexit builds, which a loader drops from the
// spec where the kernel cannot load them.
func ReturnTracingPrograms() []string {
	out := make([]string, 0, len(returnTracing))
	for _, name := range returnTracing {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// attachReturn attaches a return probe as fexit when the collection holds
// its fexit build and the kernel accepts it, and through viaKprobe
// otherwise.
func attachReturn(coll *ebpf.Collection, kretName string, viaKprobe func() (link.Link, error)) (link.Link, error) {
	if fexit := coll.Programs[returnTracing[kretName]]; fexit != nil {
		l, err := attachTracing(fexit)
		if err == nil {
			logger.Debug("Return probe attached as fexit", zap.String("prog", kretName))
			return l, nil
		}
		logger.Info("fexit could not attach; this return probe uses a kretprobe, which can drop returns on a busy node",
			zap.String("prog", kretName), zap.Error(err))
	}
	return viaKprobe()
}

// attachProbe attaches a kprobe, or a return probe preferring fexit.
func attachProbe(coll *ebpf.Collection, progName, symbol string, prog *ebpf.Program) (link.Link, error) {
	return attachReturn(coll, progName, func() (link.Link, error) {
		return attachKprobe(progName, symbol, prog)
	})
}

// ReturnTracingPairs maps each kretprobe that has an fexit build to it.
func ReturnTracingPairs() map[string]string {
	out := make(map[string]string, len(returnTracing))
	for k, v := range returnTracing {
		out[k] = v
	}
	return out
}
