package loader

import (
	"testing"

	"github.com/cilium/ebpf"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/probes"
)

func TestEveryFexitBuildReturnsFromTheSameFunctionAsItsKretprobe(t *testing.T) {
	original := config.BPFObjectPath
	t.Cleanup(func() { config.BPFObjectPath = original })
	config.BPFObjectPath = findBPFObjectPath()
	spec, err := LoadPodtrace()
	if err != nil {
		t.Skipf("BPF object not built in this environment: %v", err)
	}
	for kret, fexit := range probes.ReturnTracingPairs() {
		k, f := spec.Programs[kret], spec.Programs[fexit]
		if k == nil || f == nil {
			t.Errorf("%s or %s is missing from the object", kret, fexit)
			continue
		}
		if f.Type != ebpf.Tracing || f.AttachType != ebpf.AttachTraceFExit {
			t.Errorf("%s is %v/%v, want an fexit tracing program", fexit, f.Type, f.AttachType)
		}
		if f.AttachTo != k.AttachTo {
			t.Errorf("%s returns from %q but %s from %q", fexit, f.AttachTo, kret, k.AttachTo)
		}
	}
}
