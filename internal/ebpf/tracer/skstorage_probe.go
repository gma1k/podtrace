package tracer

import (
	"errors"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"go.uber.org/zap"

	"github.com/podtrace/podtrace/internal/logger"
)

// skStorageCrossContextResult holds the outcome of the one-shot
// HaveSkStorageCrossContext capability probe.
type skStorageCrossContextResult struct {
	mapType        bool
	cgroupSkbRead  bool
	kprobeWrite    bool
}

var (
	skStorageProbeOnce   sync.Once
	skStorageProbeResult skStorageCrossContextResult
)

// viable reports whether every capability required for the cross-context
// sk_storage design holds on this kernel.
func (r skStorageCrossContextResult) viable() bool {
	return r.mapType && r.cgroupSkbRead && r.kprobeWrite
}

// HaveSkStorageCrossContext reports whether the running kernel can share a
// BPF_MAP_TYPE_SK_STORAGE map between a socket-layer kprobe producer
// (process context, where bpf_get_current_comm is valid) and a cgroup_skb
// consumer.
func HaveSkStorageCrossContext() bool {
	skStorageProbeOnce.Do(func() {
		skStorageProbeResult = skStorageCrossContextResult{
			mapType:       probeSupported(features.HaveMapType(ebpf.SkStorage), "map_type_sk_storage"),
			cgroupSkbRead: probeSupported(features.HaveProgramHelper(ebpf.CGroupSKB, asm.FnSkStorageGet), "cgroup_skb_sk_storage_get"),
			kprobeWrite:   probeSupported(features.HaveProgramHelper(ebpf.Kprobe, asm.FnSkStorageGet), "kprobe_sk_storage_get"),
		}
		logger.Info("sk_storage cross-context capability probe (attribution GATE A)",
			zap.Bool("viable", skStorageProbeResult.viable()),
			zap.Bool("map_type_sk_storage", skStorageProbeResult.mapType),
			zap.Bool("cgroup_skb_sk_storage_get", skStorageProbeResult.cgroupSkbRead),
			zap.Bool("kprobe_sk_storage_get", skStorageProbeResult.kprobeWrite),
		)
	})
	return skStorageProbeResult.viable()
}

// probeSupported collapses a features probe error into a boolean,
// logging inconclusive results.
func probeSupported(err error, leg string) bool {
	if err == nil {
		return true
	}
	if !errors.Is(err, ebpf.ErrNotSupported) {
		logger.Warn("sk_storage capability probe inconclusive; treating as unsupported",
			zap.String("leg", leg), zap.Error(err))
	}
	return false
}