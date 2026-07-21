package main

import (
	"context"
	"errors"
	"testing"

	"github.com/podtrace/podtrace/internal/ebpf"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/pkg/tracer"
)

type recordingContainerTracer struct {
	lastTargets []ebpf.ContainerProbeTarget
	targetsErr  error
}

func (r *recordingContainerTracer) SetCgroups([]string) error   { return nil }
func (r *recordingContainerTracer) AttachToCgroup(string) error { return nil }
func (r *recordingContainerTracer) SetContainerID(string) error { return nil }
func (r *recordingContainerTracer) Start(context.Context, chan<- *events.Event) error {
	return nil
}
func (r *recordingContainerTracer) Stop() error { return nil }

func (r *recordingContainerTracer) SetContainerTargets(targets []ebpf.ContainerProbeTarget) error {
	r.lastTargets = targets
	return r.targetsErr
}

var _ ebpf.TracerInterface = (*recordingContainerTracer)(nil)

func TestEbpfBackendAdapter_SetContainerTargets_ConvertsPIDs(t *testing.T) {
	rt := &recordingContainerTracer{}
	adapter := &ebpfBackendAdapter{tr: rt}

	err := adapter.SetContainerTargets([]tracer.ContainerUprobeTarget{
		{ContainerID: "with-pid", PID: 4242},
		{ContainerID: "no-pid", PID: 0},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rt.lastTargets) != 2 {
		t.Fatalf("expected 2 converted targets, got %d: %+v", len(rt.lastTargets), rt.lastTargets)
	}

	withPID := rt.lastTargets[0]
	if withPID.ID != "with-pid" {
		t.Errorf("target[0].ID = %q, want %q", withPID.ID, "with-pid")
	}
	if len(withPID.PIDs) != 1 || withPID.PIDs[0] != 4242 {
		t.Errorf("target[0].PIDs = %v, want [4242]", withPID.PIDs)
	}

	noPID := rt.lastTargets[1]
	if noPID.ID != "no-pid" {
		t.Errorf("target[1].ID = %q, want %q", noPID.ID, "no-pid")
	}
	if len(noPID.PIDs) != 0 {
		t.Errorf("target[1].PIDs = %v, want empty (PID==0 must not add a PID)", noPID.PIDs)
	}
}

func TestEbpfBackendAdapter_SetContainerTargets_PropagatesError(t *testing.T) {
	wantErr := errors.New("reconcile boom")
	rt := &recordingContainerTracer{targetsErr: wantErr}
	adapter := &ebpfBackendAdapter{tr: rt}

	err := adapter.SetContainerTargets([]tracer.ContainerUprobeTarget{{ContainerID: "c"}})
	if !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want %v", err, wantErr)
	}
}

func TestMockTracer_SetCgroups_DefaultViaAdapter(t *testing.T) {
	m := &mockTracer{}
	adapter := &ebpfBackendAdapter{tr: m}

	if err := adapter.SetCgroups([]tracer.CgroupTarget{{CgroupPath: "/sys/fs/cgroup/a"}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMockTracer_SetCgroups_CustomFuncViaAdapter(t *testing.T) {
	var got []string
	m := &mockTracer{
		setCgroupsFunc: func(paths []string) error {
			got = paths
			return nil
		},
	}
	adapter := &ebpfBackendAdapter{tr: m}

	err := adapter.SetCgroups([]tracer.CgroupTarget{
		{CgroupPath: "/sys/fs/cgroup/a"},
		{CgroupPath: ""},
		{CgroupPath: "/sys/fs/cgroup/b"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[0] != "/sys/fs/cgroup/a" || got[1] != "/sys/fs/cgroup/b" {
		t.Fatalf("mockTracer.SetCgroups received %v, want the two non-empty paths", got)
	}
}

func TestMockTracer_SetContainerTargets_ViaAdapter(t *testing.T) {
	m := &mockTracer{}
	adapter := &ebpfBackendAdapter{tr: m}

	if err := adapter.SetContainerTargets([]tracer.ContainerUprobeTarget{{ContainerID: "c", PID: 7}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
