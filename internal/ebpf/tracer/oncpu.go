package tracer

import (
	"errors"

	"github.com/gma1k/podtrace/internal/ebpf/oncpu"
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
	sampler, err := attachOnCPU(t.collection.Programs[oncpu.ProgramName])
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
