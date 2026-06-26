package main

import (
	"context"
	"errors"
	"testing"

	"github.com/podtrace/podtrace/internal/ebpf"
	"github.com/podtrace/podtrace/internal/events"
)

type multiTracer struct {
	gotCgroups   []string
	gotIDs       []string
	cgroupsErr   error
	containerErr error
}

func (m *multiTracer) SetCgroups([]string) error   { return nil }
func (m *multiTracer) AttachToCgroup(string) error { return nil }
func (m *multiTracer) SetContainerID(string) error { return nil }
func (m *multiTracer) SetContainerTargets([]ebpf.ContainerProbeTarget) error {
	return nil
}
func (m *multiTracer) Stop() error { return nil }
func (m *multiTracer) Start(context.Context, chan<- *events.Event) error {
	return nil
}

func (m *multiTracer) AttachToCgroups(paths []string) error {
	m.gotCgroups = paths
	return m.cgroupsErr
}

func (m *multiTracer) SetContainerIDs(ids []string) error {
	m.gotIDs = ids
	return m.containerErr
}

func TestAttachTracerToCgroups_MultiInterface(t *testing.T) {
	tr := &multiTracer{}
	paths := []string{"/sys/fs/cgroup/a", "/sys/fs/cgroup/b"}
	if err := attachTracerToCgroups(tr, paths); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tr.gotCgroups) != 2 || tr.gotCgroups[0] != "/sys/fs/cgroup/a" {
		t.Errorf("AttachToCgroups got %v, want all paths forwarded", tr.gotCgroups)
	}
}

func TestAttachTracerToCgroups_MultiInterfacePropagatesError(t *testing.T) {
	wantErr := errors.New("multi attach boom")
	tr := &multiTracer{cgroupsErr: wantErr}
	if err := attachTracerToCgroups(tr, []string{"/p"}); !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want %v", err, wantErr)
	}
}

func TestSetTracerContainerIDs_MultiInterface(t *testing.T) {
	tr := &multiTracer{}
	ids := []string{"cid-1", "cid-2"}
	if err := setTracerContainerIDs(tr, ids); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tr.gotIDs) != 2 || tr.gotIDs[1] != "cid-2" {
		t.Errorf("SetContainerIDs got %v, want all IDs forwarded", tr.gotIDs)
	}
}

func TestSetTracerContainerIDs_MultiInterfacePropagatesError(t *testing.T) {
	wantErr := errors.New("multi setid boom")
	tr := &multiTracer{containerErr: wantErr}
	if err := setTracerContainerIDs(tr, []string{"x"}); !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want %v", err, wantErr)
	}
}
