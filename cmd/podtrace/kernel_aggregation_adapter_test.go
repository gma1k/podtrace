package main

import (
	"errors"
	"testing"

	"github.com/gma1k/podtrace/internal/ebpf"
	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
)

type aggCapableTracer struct {
	ebpf.TracerInterface
	mode  kernelagg.Mode
	rows  []kernelagg.Row
	drain error
}

func (a *aggCapableTracer) SetKernelAggregationMode(mode kernelagg.Mode) error {
	a.mode = mode
	return nil
}

func (a *aggCapableTracer) DrainKernelMetrics() ([]kernelagg.Row, error) {
	if a.drain != nil {
		return nil, a.drain
	}
	return a.rows, nil
}

type plainTracer struct{ ebpf.TracerInterface }

func TestTheAdapterForwardsAggregationToTheTracer(t *testing.T) {
	tr := &aggCapableTracer{rows: []kernelagg.Row{{Key: kernelagg.Key{CgroupID: 5}}}}
	a := &ebpfBackendAdapter{tr: tr}

	if err := a.SetKernelAggregationMode(kernelagg.ModeBypass); err != nil {
		t.Fatalf("SetKernelAggregationMode: %v", err)
	}
	if tr.mode != kernelagg.ModeBypass {
		t.Errorf("tracer saw mode %v, want bypass", tr.mode)
	}

	rows, err := a.DrainKernelMetrics()
	if err != nil {
		t.Fatalf("DrainKernelMetrics: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("forwarded %d rows, want 1", len(rows))
	}
}

func TestTheAdapterReportsABackendThatCannotAggregate(t *testing.T) {
	a := &ebpfBackendAdapter{tr: &plainTracer{}}

	if err := a.SetKernelAggregationMode(kernelagg.ModeOn); !errors.Is(err, ErrNoKernelAggregation) {
		t.Errorf("SetKernelAggregationMode = %v, want ErrNoKernelAggregation. The agent decides "+
			"whether to fall back to the event path on this error; forwarding silently would "+
			"leave the probes off while the agent believed aggregation was running", err)
	}
	if _, err := a.DrainKernelMetrics(); !errors.Is(err, ErrNoKernelAggregation) {
		t.Errorf("DrainKernelMetrics = %v, want ErrNoKernelAggregation", err)
	}
}

func TestTheAdapterSurfacesADrainFailure(t *testing.T) {
	a := &ebpfBackendAdapter{tr: &aggCapableTracer{drain: errors.New("map read failed")}}
	if _, err := a.DrainKernelMetrics(); err == nil {
		t.Error("a drain failure was swallowed; the interval would look idle rather than broken")
	}
}
