package tracer_test

import (
	"context"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/pkg/tracer"
)

type snapshotBackend struct {
	*mockBackend
	smu       sync.Mutex
	snapshots [][]tracer.CgroupTarget
}

func (b *snapshotBackend) SetCgroups(targets []tracer.CgroupTarget) error {
	b.smu.Lock()
	b.snapshots = append(b.snapshots, append([]tracer.CgroupTarget(nil), targets...))
	b.smu.Unlock()
	return b.mockBackend.SetCgroups(targets)
}

func (b *snapshotBackend) lastSnapshot() []tracer.CgroupTarget {
	b.smu.Lock()
	defer b.smu.Unlock()
	if len(b.snapshots) == 0 {
		return nil
	}
	return append([]tracer.CgroupTarget(nil), b.snapshots[len(b.snapshots)-1]...)
}

type uprobeTargetBackend struct {
	*mockBackend
	rmu  sync.Mutex
	ids  []string
	err  error
	seen bool
}

func (b *uprobeTargetBackend) SetContainerTargets(targets []tracer.ContainerUprobeTarget) error {
	b.rmu.Lock()
	defer b.rmu.Unlock()
	b.seen = true
	b.ids = nil
	for _, t := range targets {
		b.ids = append(b.ids, t.ContainerID)
	}
	return b.err
}

func (b *uprobeTargetBackend) observed() []string {
	b.rmu.Lock()
	defer b.rmu.Unlock()
	out := append([]string(nil), b.ids...)
	sort.Strings(out)
	return out
}

type erroringContainerIDsBackend struct {
	*mockBackend
	err error
}

func (b *erroringContainerIDsBackend) SetContainerIDs([]string) error { return b.err }

type perIDBackend struct {
	*mockBackend
	pmu sync.Mutex
	ids []string
	err error
}

func (b *perIDBackend) SetContainerID(id string) error {
	b.pmu.Lock()
	defer b.pmu.Unlock()
	b.ids = append(b.ids, id)
	return b.err
}

func (b *perIDBackend) observed() []string {
	b.pmu.Lock()
	defer b.pmu.Unlock()
	out := append([]string(nil), b.ids...)
	sort.Strings(out)
	return out
}

func runEngineWith(t *testing.T, backend tracer.TracerBackend, obs tracer.EngineObserver) chan<- tracer.TargetSet {
	t.Helper()
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{&recordingExporter{name: "rec"}},
		tracer.Config{EventBufferSize: 16, ExportBatchSize: 4, Observer: obs})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	targets := make(chan tracer.TargetSet, 4)
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, targets) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run returned: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Run did not return")
		}
	})
	return targets
}

func TestEngineRunRefusesANilTargetsChannel(t *testing.T) {
	eng, err := tracer.NewEngine(&mockBackend{},
		[]tracer.Exporter{&recordingExporter{name: "rec"}}, tracer.Config{})
	if err != nil {
		t.Fatal(err)
	}

	if err := eng.Run(context.Background(), nil); err == nil {
		t.Fatal("Run accepted a nil targets channel. Without one the engine would attach to " +
			"nothing and block forever, reporting healthy while capturing no events")
	}
}

func TestDuplicateAndBlankCgroupPathsCollapse(t *testing.T) {
	backend := &snapshotBackend{mockBackend: &mockBackend{}}
	targets := runEngineWith(t, backend, nil)

	targets <- tracer.TargetSet{
		{CgroupPath: "/cg/a", ContainerID: "a"},
		{CgroupPath: "/cg/a", ContainerID: "a-again"},
		{CgroupPath: "", ContainerID: "no-cgroup"},
		{CgroupPath: "/cg/b", ContainerID: "b"},
	}
	waitUntil(t, 2*time.Second, func() bool { return len(backend.lastSnapshot()) > 0 })

	got := backend.lastSnapshot()
	if len(got) != 2 {
		t.Errorf("snapshot = %+v, want 2 entries. A pod listed twice, or one whose cgroup path "+
			"has not been resolved yet, must not attach the same cgroup twice", got)
	}
}

func TestUprobeReconcilerSeesEachContainerOnce(t *testing.T) {
	backend := &uprobeTargetBackend{mockBackend: &mockBackend{}}
	targets := runEngineWith(t, backend, nil)

	targets <- tracer.TargetSet{
		{CgroupPath: "/cg/a", ContainerID: "shared", ContainerPID: 111},
		{CgroupPath: "/cg/b", ContainerID: "shared", ContainerPID: 111},
		{CgroupPath: "/cg/c", ContainerID: "", ContainerPID: 222},
		{CgroupPath: "/cg/d", ContainerID: "other", ContainerPID: 333},
	}
	waitUntil(t, 2*time.Second, func() bool { return len(backend.observed()) > 0 })

	got := backend.observed()
	want := []string{"other", "shared"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("targets = %v, want %v. A container with two cgroups must be attached once, "+
			"and one with no ID yet has no binary to probe", got, want)
	}
}

func TestAttachStageFailuresAreReportedByStage(t *testing.T) {
	failure := errors.New("attach refused")

	cases := []struct {
		name    string
		backend tracer.TracerBackend
		stage   string
	}{
		{"set_container_targets", &uprobeTargetBackend{mockBackend: &mockBackend{}, err: failure}, "set_container_targets"},
		{"set_container_ids", &erroringContainerIDsBackend{mockBackend: &mockBackend{}, err: failure}, "set_container_ids"},
		{"set_container_id", &perIDBackend{mockBackend: &mockBackend{}, err: failure}, "set_container_id"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obs := &targetErrObserver{}
			targets := runEngineWith(t, tc.backend, obs)

			targets <- tracer.TargetSet{{CgroupPath: "/cg/a", ContainerID: "a", ContainerPID: 1}}
			waitUntil(t, 2*time.Second, func() bool {
				stages, _ := obs.snapshot()
				return len(stages) > 0
			})

			stages, errs := obs.snapshot()
			if len(stages) == 0 || stages[0] != tc.stage {
				t.Fatalf("stages = %v, want %q first. A uprobe that failed to attach must name "+
					"the stage that failed, not read as a healthy attach", stages, tc.stage)
			}
			if len(errs) == 0 || !errors.Is(errs[0], failure) {
				t.Errorf("errs = %v, want the backend failure", errs)
			}
		})
	}
}

func TestFallbackBackendAttachesEachContainerOnce(t *testing.T) {
	backend := &perIDBackend{mockBackend: &mockBackend{}}
	targets := runEngineWith(t, backend, nil)

	targets <- tracer.TargetSet{
		{CgroupPath: "/cg/a", ContainerID: "shared"},
		{CgroupPath: "/cg/b", ContainerID: "shared"},
		{CgroupPath: "/cg/c", ContainerID: ""},
		{CgroupPath: "/cg/d", ContainerID: "other"},
	}
	waitUntil(t, 2*time.Second, func() bool { return len(backend.observed()) >= 2 })

	got := backend.observed()
	want := []string{"other", "shared"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("SetContainerID calls = %v, want %v exactly once each", got, want)
	}
}

type closingBackend struct {
	*mockBackend
	cmu sync.Mutex
	ch  chan<- *events.Event
}

func (b *closingBackend) Start(ctx context.Context, ch chan<- *events.Event) error {
	if err := b.mockBackend.Start(ctx, ch); err != nil {
		return err
	}
	b.cmu.Lock()
	b.ch = ch
	b.cmu.Unlock()
	return nil
}

func (b *closingBackend) channel() chan<- *events.Event {
	b.cmu.Lock()
	defer b.cmu.Unlock()
	return b.ch
}

func TestAClosedEventChannelFlushesThePendingBatch(t *testing.T) {
	backend := &closingBackend{mockBackend: &mockBackend{}}
	exporter := &recordingExporter{name: "rec"}
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{exporter},
		tracer.Config{EventBufferSize: 16, ExportBatchSize: 1024, ExportFlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	targets := make(chan tracer.TargetSet, 1)
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, targets) }()

	waitUntil(t, 2*time.Second, func() bool { return backend.channel() != nil })

	ch := backend.channel()
	for i := 0; i < 3; i++ {
		ch <- &events.Event{}
	}
	close(ch)

	waitUntil(t, 2*time.Second, func() bool { return exporter.totalEvents() == 3 })

	if got := exporter.totalEvents(); got != 3 {
		t.Errorf("exported %d events, want 3. A backend that finishes streaming closes the "+
			"channel; if that path dropped the partial batch every event since the last flush "+
			"would be lost with no error anywhere", got)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the event channel closed")
	}
}

type gatedExporter struct {
	*recordingExporter
	gate    chan struct{}
	blocked atomic.Bool
}

func (e *gatedExporter) Export(ctx context.Context, batch []*events.Event) error {
	if e.blocked.CompareAndSwap(false, true) {
		<-e.gate
	}
	return e.recordingExporter.Export(ctx, batch)
}

func TestEventsStillBufferedAtShutdownAreFlushed(t *testing.T) {
	const buffered = 40

	backend := &closingBackend{mockBackend: &mockBackend{}}
	exporter := &gatedExporter{
		recordingExporter: &recordingExporter{name: "gated"},
		gate:              make(chan struct{}),
	}
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{exporter},
		tracer.Config{EventBufferSize: 64, ExportBatchSize: 2, ExportFlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	targets := make(chan tracer.TargetSet, 1)
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, targets) }()

	waitUntil(t, 2*time.Second, func() bool { return backend.channel() != nil })
	ch := backend.channel()

	for i := 0; i < 2; i++ {
		ch <- &events.Event{}
	}
	waitUntil(t, 2*time.Second, func() bool { return exporter.blocked.Load() })

	for i := 0; i < buffered; i++ {
		ch <- &events.Event{}
	}
	cancel()
	close(exporter.gate)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}

	if got := exporter.totalEvents(); got != buffered+2 {
		t.Errorf("exported %d events, want %d. Events already queued when shutdown begins must "+
			"be drained and flushed; dropping them loses the very window an operator is most "+
			"likely to be looking at", got, buffered+2)
	}
}
