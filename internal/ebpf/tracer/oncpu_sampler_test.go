package tracer

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/gma1k/podtrace/internal/ebpf/oncpu"
)

func TestTheOnCPUSamplerNeedsALoadedObject(t *testing.T) {
	var none *Tracer
	if _, err := none.StartOnCPUSampler(); err == nil {
		t.Error("a nil tracer started the sampler")
	}
	if d, err := none.DrainOnCPUSamples(); err != nil || len(d.Samples) != 0 {
		t.Errorf("a nil tracer drained %+v, %v", d, err)
	}

	bare := &Tracer{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}, Programs: map[string]*ebpf.Program{}}}
	if _, err := bare.StartOnCPUSampler(); err == nil {
		t.Error("an object without the sampler maps started the sampler")
	}
	if _, err := bare.DrainOnCPUSamples(); err == nil {
		t.Error("an object without the sampler maps was drained")
	}
	bare.stopOnCPUSampler()
}

func TestARunningSamplerIsReusedAndStopped(t *testing.T) {
	tr := &Tracer{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}, onCPUSampler: &oncpu.Sampler{}}
	if cpus, err := tr.StartOnCPUSampler(); err != nil || cpus != 0 {
		t.Errorf("StartOnCPUSampler on a running sampler = %d, %v", cpus, err)
	}
	tr.stopOnCPUSampler()
	if tr.onCPUSampler != nil {
		t.Error("the sampler was not released")
	}
}

func TestAnAttachFailureLeavesNoSampler(t *testing.T) {
	enabled := &ebpf.Map{}
	tr := &Tracer{collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{oncpu.EnabledMapName: enabled}}}
	orig := attachOnCPU
	attachOnCPU = func(*ebpf.Program) (*oncpu.Sampler, error) { return nil, errTestAttach }
	t.Cleanup(func() { attachOnCPU = orig })
	if _, err := tr.StartOnCPUSampler(); !errors.Is(err, errTestAttach) || tr.onCPUSampler != nil {
		t.Errorf("StartOnCPUSampler = %v, sampler %v", err, tr.onCPUSampler)
	}
}

var errTestAttach = errors.New("attach failed")
