package main

import (
	"errors"
	"testing"

	"github.com/gma1k/podtrace/internal/ebpf"
	"github.com/gma1k/podtrace/internal/ebpf/oncpu"
)

type onCPUCapableTracer struct {
	ebpf.TracerInterface
	startErr error
	drained  oncpu.Drained
}

func (s *onCPUCapableTracer) StartOnCPUSampler() (int, error) { return 8, s.startErr }

func (s *onCPUCapableTracer) DrainOnCPUSamples() (oncpu.Drained, error) { return s.drained, nil }

func TestTheAdapterForwardsTheOnCPUSamplerToTheTracer(t *testing.T) {
	a := &ebpfBackendAdapter{tr: &onCPUCapableTracer{drained: oncpu.Drained{Unresolved: 3}}}
	if cpus, err := a.StartOnCPUSampler(); err != nil || cpus != 8 {
		t.Errorf("StartOnCPUSampler = %d, %v", cpus, err)
	}
	if d, err := a.DrainOnCPUSamples(); err != nil || d.Unresolved != 3 {
		t.Errorf("DrainOnCPUSamples = %+v, %v", d, err)
	}
	boom := errors.New("no perf events")
	if _, err := (&ebpfBackendAdapter{tr: &onCPUCapableTracer{startErr: boom}}).StartOnCPUSampler(); !errors.Is(err, boom) {
		t.Errorf("a start failure was not forwarded: %v", err)
	}
}

func TestTheAdapterReportsABackendWithoutTheOnCPUSampler(t *testing.T) {
	a := &ebpfBackendAdapter{tr: &plainTracer{}}
	if _, err := a.StartOnCPUSampler(); !errors.Is(err, ErrNoOnCPUSampler) {
		t.Errorf("StartOnCPUSampler = %v", err)
	}
	if _, err := a.DrainOnCPUSamples(); !errors.Is(err, ErrNoOnCPUSampler) {
		t.Errorf("DrainOnCPUSamples = %v", err)
	}
}
