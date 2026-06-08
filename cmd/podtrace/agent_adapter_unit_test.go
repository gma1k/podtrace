package main

import (
	"context"
	"errors"
	"testing"

	"github.com/podtrace/podtrace/internal/ebpf"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/pkg/tracer"
)

// fakeTracer is a hand-rolled ebpf.TracerInterface implementation that
// records the arguments it receives and returns configurable errors.
// It deliberately does NOT implement SetEnabledCategories so the
// adapter's optional categoryGateable type-assertion takes its !ok path.
type fakeTracer struct {
	setCgroupsArg  []string
	attachArg      string
	containerIDArg string
	startCalled    bool
	stopCalled     bool
	startCh        chan<- *events.Event

	setCgroupsErr  error
	attachErr      error
	containerIDErr error
	startErr       error
	stopErr        error
}

func (f *fakeTracer) SetCgroups(paths []string) error {
	f.setCgroupsArg = paths
	return f.setCgroupsErr
}

func (f *fakeTracer) AttachToCgroup(path string) error {
	f.attachArg = path
	return f.attachErr
}

func (f *fakeTracer) SetContainerID(id string) error {
	f.containerIDArg = id
	return f.containerIDErr
}

func (f *fakeTracer) Start(_ context.Context, ch chan<- *events.Event) error {
	f.startCalled = true
	f.startCh = ch
	return f.startErr
}

func (f *fakeTracer) Stop() error {
	f.stopCalled = true
	return f.stopErr
}

var _ ebpf.TracerInterface = (*fakeTracer)(nil)

// gateableFakeTracer embeds fakeTracer and additionally satisfies the
// optional categoryGateable interface so the adapter takes its ok path.
type gateableFakeTracer struct {
	fakeTracer
	categoriesArg  []string
	categoriesCall bool
	categoriesErr  error
}

func (g *gateableFakeTracer) SetEnabledCategories(categories []string) error {
	g.categoriesCall = true
	g.categoriesArg = categories
	return g.categoriesErr
}

var _ ebpf.TracerInterface = (*gateableFakeTracer)(nil)

func TestEbpfBackendAdapter_SetCgroups_FiltersEmptyPaths(t *testing.T) {
	fake := &fakeTracer{}
	adapter := &ebpfBackendAdapter{tr: fake}

	targets := []tracer.CgroupTarget{
		{CgroupPath: "/sys/fs/cgroup/a", ContainerID: "c1"},
		{CgroupPath: "", ContainerID: "c2"},
		{CgroupPath: "/sys/fs/cgroup/b", ContainerID: "c3"},
		{CgroupPath: "", ContainerID: "c4"},
	}

	if err := adapter.SetCgroups(targets); err != nil {
		t.Fatalf("SetCgroups returned unexpected error: %v", err)
	}

	want := []string{"/sys/fs/cgroup/a", "/sys/fs/cgroup/b"}
	if len(fake.setCgroupsArg) != len(want) {
		t.Fatalf("fake received %v, want %v", fake.setCgroupsArg, want)
	}
	for i, p := range want {
		if fake.setCgroupsArg[i] != p {
			t.Errorf("path[%d] = %q, want %q", i, fake.setCgroupsArg[i], p)
		}
	}
}

func TestEbpfBackendAdapter_SetCgroups_PropagatesError(t *testing.T) {
	wantErr := errors.New("boom")
	fake := &fakeTracer{setCgroupsErr: wantErr}
	adapter := &ebpfBackendAdapter{tr: fake}

	err := adapter.SetCgroups([]tracer.CgroupTarget{{CgroupPath: "/x"}})
	if !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want %v", err, wantErr)
	}
}

func TestEbpfBackendAdapter_SetCgroups_AllEmpty(t *testing.T) {
	fake := &fakeTracer{}
	adapter := &ebpfBackendAdapter{tr: fake}

	if err := adapter.SetCgroups([]tracer.CgroupTarget{{CgroupPath: ""}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.setCgroupsArg) != 0 {
		t.Fatalf("expected no paths forwarded, got %v", fake.setCgroupsArg)
	}
}

func TestEbpfBackendAdapter_AttachToCgroup(t *testing.T) {
	fake := &fakeTracer{}
	adapter := &ebpfBackendAdapter{tr: fake}

	if err := adapter.AttachToCgroup("/sys/fs/cgroup/z"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.attachArg != "/sys/fs/cgroup/z" {
		t.Errorf("attachArg = %q, want %q", fake.attachArg, "/sys/fs/cgroup/z")
	}

	wantErr := errors.New("attach failed")
	failing := &ebpfBackendAdapter{tr: &fakeTracer{attachErr: wantErr}}
	if err := failing.AttachToCgroup("/p"); !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want %v", err, wantErr)
	}
}

func TestEbpfBackendAdapter_SetContainerID(t *testing.T) {
	fake := &fakeTracer{}
	adapter := &ebpfBackendAdapter{tr: fake}

	if err := adapter.SetContainerID("abc123"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.containerIDArg != "abc123" {
		t.Errorf("containerIDArg = %q, want %q", fake.containerIDArg, "abc123")
	}

	wantErr := errors.New("setid failed")
	failing := &ebpfBackendAdapter{tr: &fakeTracer{containerIDErr: wantErr}}
	if err := failing.SetContainerID("x"); !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want %v", err, wantErr)
	}
}

func TestEbpfBackendAdapter_Start(t *testing.T) {
	fake := &fakeTracer{}
	adapter := &ebpfBackendAdapter{tr: fake}

	ch := make(chan *events.Event)
	if err := adapter.Start(context.Background(), ch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fake.startCalled {
		t.Error("expected Start to be delegated to the fake tracer")
	}

	wantErr := errors.New("start failed")
	failing := &ebpfBackendAdapter{tr: &fakeTracer{startErr: wantErr}}
	if err := failing.Start(context.Background(), ch); !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want %v", err, wantErr)
	}
}

func TestEbpfBackendAdapter_Stop(t *testing.T) {
	fake := &fakeTracer{}
	adapter := &ebpfBackendAdapter{tr: fake}

	if err := adapter.Stop(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fake.stopCalled {
		t.Error("expected Stop to be delegated to the fake tracer")
	}

	wantErr := errors.New("stop failed")
	failing := &ebpfBackendAdapter{tr: &fakeTracer{stopErr: wantErr}}
	if err := failing.Stop(); !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want %v", err, wantErr)
	}
}

func TestEbpfBackendAdapter_SetEnabledCategories_NotGateable(t *testing.T) {
	adapter := &ebpfBackendAdapter{tr: &fakeTracer{}}
	if err := adapter.SetEnabledCategories([]string{"net", "dns"}); err != nil {
		t.Fatalf("expected nil for non-gateable tracer, got %v", err)
	}
}

func TestEbpfBackendAdapter_SetEnabledCategories_Gateable(t *testing.T) {
	g := &gateableFakeTracer{}
	adapter := &ebpfBackendAdapter{tr: g}

	cats := []string{"net", "fs"}
	if err := adapter.SetEnabledCategories(cats); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !g.categoriesCall {
		t.Fatal("expected SetEnabledCategories to be delegated")
	}
	if len(g.categoriesArg) != 2 || g.categoriesArg[0] != "net" || g.categoriesArg[1] != "fs" {
		t.Errorf("categoriesArg = %v, want %v", g.categoriesArg, cats)
	}

	wantErr := errors.New("gate failed")
	failing := &ebpfBackendAdapter{tr: &gateableFakeTracer{categoriesErr: wantErr}}
	if err := failing.SetEnabledCategories(cats); !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want %v", err, wantErr)
	}
}

// Compile-time confirmation that the adapter satisfies both the base
// backend contract and the optional gating capability.
var (
	_ tracer.TracerBackend    = (*ebpfBackendAdapter)(nil)
	_ tracer.CategoryGateable = (*ebpfBackendAdapter)(nil)
)

func TestAgentBackendFactory(t *testing.T) {
	backend, err := agentBackendFactory()
	if err == nil && backend == nil {
		t.Fatal("agentBackendFactory returned (nil, nil); want a backend or an error")
	}
	if err != nil {
		t.Logf("agentBackendFactory returned error (expected without BPF): %v", err)
		if backend != nil {
			t.Errorf("expected nil backend when error is returned, got %#v", backend)
		}
		return
	}
	t.Logf("agentBackendFactory returned a usable backend: %T", backend)
}
