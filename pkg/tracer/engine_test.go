package tracer_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/pkg/tracer"
)

// mockBackend is a minimal TracerBackend implementation that records
// attach/start/stop activity for assertions.
type mockBackend struct {
	mu              sync.Mutex
	active          map[string]struct{}
	attachHistory   []string
	setCalls        int
	started         bool
	stopped         bool
	startErr        error
	attachErr       error
	setCgroupsErr   error
	setContainerErr error
	eventCh         chan<- *events.Event
}

func (m *mockBackend) AttachToCgroup(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.attachErr != nil {
		return m.attachErr
	}
	if m.active == nil {
		m.active = map[string]struct{}{}
	}
	m.active[path] = struct{}{}
	m.attachHistory = append(m.attachHistory, path)
	return nil
}

func (m *mockBackend) SetCgroups(targets []tracer.CgroupTarget) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.setCgroupsErr != nil {
		return m.setCgroupsErr
	}
	m.setCalls++
	next := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		if t.CgroupPath == "" {
			continue
		}
		next[t.CgroupPath] = struct{}{}
		if _, was := m.active[t.CgroupPath]; !was {
			m.attachHistory = append(m.attachHistory, t.CgroupPath)
		}
	}
	m.active = next
	return nil
}

func (m *mockBackend) SetContainerID(_ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.setContainerErr
}

func (m *mockBackend) Start(_ context.Context, ch chan<- *events.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.startErr != nil {
		return m.startErr
	}
	m.started = true
	m.eventCh = ch
	return nil
}

func (m *mockBackend) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopped = true
	return nil
}

func (m *mockBackend) emit(t *testing.T, ev *events.Event) {
	m.mu.Lock()
	ch := m.eventCh
	m.mu.Unlock()
	if ch == nil {
		t.Fatal("backend not started")
	}
	ch <- ev
}

// activePaths returns the current active set (after the most recent
// SetCgroups call).
func (m *mockBackend) activePaths() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.active))
	for p := range m.active {
		out = append(out, p)
	}
	return out
}

// attachedPaths returns the cumulative history of paths the backend has
// seen attached at any point.
func (m *mockBackend) attachedPaths() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.attachHistory))
	copy(out, m.attachHistory)
	return out
}

// recordingExporter captures every batch it receives, synchronously.
type recordingExporter struct {
	mu         sync.Mutex
	name       string
	batches    [][]*events.Event
	exportErr  error
	closeErr   error
	closeCalls int
}

func (e *recordingExporter) Name() string { return e.name }

func (e *recordingExporter) Export(_ context.Context, batch []*events.Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.exportErr != nil {
		return e.exportErr
	}
	cp := make([]*events.Event, len(batch))
	copy(cp, batch)
	e.batches = append(e.batches, cp)
	return nil
}

func (e *recordingExporter) Close(_ context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closeCalls++
	return e.closeErr
}

func (e *recordingExporter) totalEvents() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	total := 0
	for _, b := range e.batches {
		total += len(b)
	}
	return total
}

func TestNewEngine_Validation(t *testing.T) {
	t.Run("nil-backend-rejected", func(t *testing.T) {
		if _, err := tracer.NewEngine(nil, []tracer.Exporter{&recordingExporter{name: "x"}}, tracer.Config{}); err == nil {
			t.Fatal("expected error for nil backend")
		}
	})
	t.Run("empty-exporters-rejected", func(t *testing.T) {
		if _, err := tracer.NewEngine(&mockBackend{}, nil, tracer.Config{}); err == nil {
			t.Fatal("expected error for empty exporters")
		}
	})
	t.Run("defaults-applied", func(t *testing.T) {
		e, err := tracer.NewEngine(&mockBackend{}, []tracer.Exporter{&recordingExporter{name: "x"}}, tracer.Config{})
		if err != nil {
			t.Fatal(err)
		}
		if e == nil {
			t.Fatal("engine is nil")
		}
	})
}

// TestEngine_TargetAttachment asserts that the engine attaches to every
// unique cgroup in the target set and does not re-attach a cgroup that
// appeared in the previous snapshot (backend idempotency is the contract).
func TestEngine_TargetAttachment(t *testing.T) {
	backend := &mockBackend{}
	exporter := &recordingExporter{name: "rec"}
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{exporter}, tracer.Config{EventBufferSize: 16, ExportBatchSize: 4})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targets := make(chan tracer.TargetSet, 4)
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, targets) }()

	targets <- tracer.TargetSet{
		{CgroupPath: "/sys/fs/cgroup/a", ContainerID: "a"},
		{CgroupPath: "/sys/fs/cgroup/b", ContainerID: "b"},
	}
	waitUntil(t, 2*time.Second, func() bool { return len(backend.activePaths()) == 2 })

	targets <- tracer.TargetSet{
		{CgroupPath: "/sys/fs/cgroup/a", ContainerID: "a"},
		{CgroupPath: "/sys/fs/cgroup/c", ContainerID: "c"},
	}
	waitUntil(t, 2*time.Second, func() bool {
		ap := backend.activePaths()
		return len(ap) == 2 && hasAll(ap, "/sys/fs/cgroup/a", "/sys/fs/cgroup/c")
	})

	active := backend.activePaths()
	if len(active) != 2 {
		t.Errorf("expected active set of 2 after replace, got %d (%v)", len(active), active)
	}
	for _, p := range active {
		if p == "/sys/fs/cgroup/b" {
			t.Errorf("stale cgroup %q remained in active set after replace", p)
		}
	}

	history := backend.attachedPaths()
	wantHistory := map[string]bool{"/sys/fs/cgroup/a": true, "/sys/fs/cgroup/b": true, "/sys/fs/cgroup/c": true}
	for _, p := range history {
		if !wantHistory[p] {
			t.Errorf("unexpected path in attach history %q", p)
		}
	}
	if len(history) != 3 {
		t.Errorf("expected 3 paths in attach history, got %d (%v)", len(history), history)
	}

	if s := eng.Stats(); s.CgroupsDetached != 1 {
		t.Errorf("CgroupsDetached=%d, want 1", s.CgroupsDetached)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned: %v", err)
	}
	if !backend.stopped {
		t.Error("backend.Stop not called")
	}
	if exporter.closeCalls != 1 {
		t.Errorf("exporter.Close called %d times, want 1", exporter.closeCalls)
	}
}

// TestEngine_EventDispatch asserts that events pushed by the backend reach
// the exporter in order, batched according to ExportBatchSize.
func TestEngine_EventDispatch(t *testing.T) {
	backend := &mockBackend{}
	exporter := &recordingExporter{name: "rec"}
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{exporter}, tracer.Config{EventBufferSize: 16, ExportBatchSize: 4})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targets := make(chan tracer.TargetSet, 1)
	targets <- tracer.TargetSet{{CgroupPath: "/c"}}

	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, targets) }()

	waitUntil(t, 2*time.Second, func() bool { return len(backend.attachedPaths()) == 1 })

	for i := 0; i < 10; i++ {
		backend.emit(t, &events.Event{Type: events.EventDNS})
	}

	// Give the dispatch loop a chance to pick them up.
	waitUntil(t, 2*time.Second, func() bool { return exporter.totalEvents() >= 8 })

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned: %v", err)
	}

	if got := exporter.totalEvents(); got != 10 {
		t.Errorf("exporter received %d events, want 10", got)
	}
}

func TestEngine_ErrorsOnBackendStartFailure(t *testing.T) {
	backend := &mockBackend{startErr: errors.New("boom")}
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{&recordingExporter{name: "x"}}, tracer.Config{})
	if err != nil {
		t.Fatal(err)
	}
	targets := make(chan tracer.TargetSet, 1)
	err = eng.Run(context.Background(), targets)
	if err == nil {
		t.Fatal("expected error when backend.Start fails")
	}
	if !containsSub(err.Error(), "backend start") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestEngine_ClosedTargetStreamShutsDownCleanly(t *testing.T) {
	backend := &mockBackend{}
	exporter := &recordingExporter{name: "x"}
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{exporter}, tracer.Config{})
	if err != nil {
		t.Fatal(err)
	}
	targets := make(chan tracer.TargetSet)
	done := make(chan error, 1)
	go func() { done <- eng.Run(context.Background(), targets) }()

	close(targets)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after target stream close")
	}
	if !backend.stopped {
		t.Error("backend.Stop not called on target stream close")
	}
}

func waitUntil(t *testing.T, d time.Duration, pred func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if pred() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("condition not met within %s", d)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// hasAll reports whether got contains every value in want (order- and
// duplicate-insensitive).
func hasAll(got []string, want ...string) bool {
	have := make(map[string]struct{}, len(got))
	for _, g := range got {
		have[g] = struct{}{}
	}
	for _, w := range want {
		if _, ok := have[w]; !ok {
			return false
		}
	}
	return true
}

func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// Satisfy unused-import linters if Config's zero value inadvertently changes.
var _ = fmt.Sprint(tracer.Config{})

// TestEngine_Stats asserts that Stats() reflects accumulated counters and
// active target count.
func TestEngine_Stats(t *testing.T) {
	backend := &mockBackend{}
	exp := &recordingExporter{name: "rec"}
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{exp}, tracer.Config{EventBufferSize: 16, ExportBatchSize: 2})
	if err != nil {
		t.Fatal(err)
	}

	if s := eng.Stats(); s.EventsReceived != 0 || s.EventsExported != 0 || s.ActiveTargets != 0 {
		t.Fatalf("pre-run stats non-zero: %+v", s)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targets := make(chan tracer.TargetSet, 2)
	targets <- tracer.TargetSet{
		{CgroupPath: "/c/a"},
		{CgroupPath: "/c/b"},
	}
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, targets) }()

	waitUntil(t, 2*time.Second, func() bool { return eng.Stats().ActiveTargets == 2 })

	for i := 0; i < 6; i++ {
		backend.emit(t, &events.Event{Type: events.EventDNS})
	}
	waitUntil(t, 2*time.Second, func() bool { return eng.Stats().EventsReceived == 6 })

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}

	final := eng.Stats()
	if final.EventsReceived != 6 {
		t.Errorf("EventsReceived=%d, want 6", final.EventsReceived)
	}
	if final.EventsExported != 6 {
		t.Errorf("EventsExported=%d, want 6 (final flush on shutdown)", final.EventsExported)
	}
	if final.ActiveTargets != 2 {
		t.Errorf("ActiveTargets=%d, want 2", final.ActiveTargets)
	}
}

// TestEngine_MultiExporterFanout asserts every registered exporter
// receives every batch.
func TestEngine_MultiExporterFanout(t *testing.T) {
	backend := &mockBackend{}
	a := &recordingExporter{name: "a"}
	b := &recordingExporter{name: "b"}
	c := &recordingExporter{name: "c"}
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{a, b, c}, tracer.Config{EventBufferSize: 16, ExportBatchSize: 2})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targets := make(chan tracer.TargetSet, 1)
	targets <- tracer.TargetSet{{CgroupPath: "/c"}}
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, targets) }()

	waitUntil(t, 2*time.Second, func() bool { return len(backend.attachedPaths()) == 1 })

	for i := 0; i < 4; i++ {
		backend.emit(t, &events.Event{Type: events.EventDNS})
	}
	waitUntil(t, 2*time.Second, func() bool {
		return a.totalEvents() == 4 && b.totalEvents() == 4 && c.totalEvents() == 4
	})

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}

	for _, ex := range []*recordingExporter{a, b, c} {
		if ex.totalEvents() != 4 {
			t.Errorf("%s: received %d, want 4", ex.name, ex.totalEvents())
		}
		if ex.closeCalls != 1 {
			t.Errorf("%s: Close called %d times, want 1", ex.name, ex.closeCalls)
		}
	}
}

// TestEngine_ExporterFailureCounted ensures that when an exporter's
// Export returns error, the engine continues pumping events and bumps
// ExporterFailure.
func TestEngine_ExporterFailureCounted(t *testing.T) {
	backend := &mockBackend{}
	bad := &recordingExporter{name: "bad", exportErr: errors.New("broken")}
	good := &recordingExporter{name: "good"}
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{bad, good}, tracer.Config{EventBufferSize: 16, ExportBatchSize: 2})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targets := make(chan tracer.TargetSet, 1)
	targets <- tracer.TargetSet{{CgroupPath: "/c"}}
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, targets) }()

	waitUntil(t, 2*time.Second, func() bool { return len(backend.attachedPaths()) == 1 })

	for i := 0; i < 4; i++ {
		backend.emit(t, &events.Event{Type: events.EventDNS})
	}
	waitUntil(t, 2*time.Second, func() bool { return good.totalEvents() == 4 })
	waitUntil(t, 2*time.Second, func() bool { return eng.Stats().ExporterFailure > 0 })

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	if good.totalEvents() != 4 {
		t.Errorf("good exporter received %d events, want 4", good.totalEvents())
	}
}

// TestEngine_AttachErrorDoesNotAbortRun ensures that a backend
// SetCgroups failure does not prevent the engine from processing later
// target sets
func TestEngine_AttachErrorDoesNotAbortRun(t *testing.T) {
	backend := &mockBackend{setCgroupsErr: errors.New("attach broken")}
	exp := &recordingExporter{name: "x"}
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{exp}, tracer.Config{})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targets := make(chan tracer.TargetSet, 2)
	targets <- tracer.TargetSet{{CgroupPath: "/will/fail"}}

	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, targets) }()

	waitUntil(t, 2*time.Second, func() bool { return eng.Stats().AttachFailure > 0 })
	backend.mu.Lock()
	backend.setCgroupsErr = nil
	backend.mu.Unlock()

	targets <- tracer.TargetSet{{CgroupPath: "/will/succeed"}}
	waitUntil(t, 2*time.Second, func() bool { return eng.Stats().ActiveTargets == 1 })

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// TestEngine_EmptyCgroupPathSkipped asserts that targets without a
// CgroupPath are silently dropped from applyTargets, matching the
// documented contract (the backend attaches by cgroup only).
func TestEngine_EmptyCgroupPathSkipped(t *testing.T) {
	backend := &mockBackend{}
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{&recordingExporter{name: "x"}}, tracer.Config{})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targets := make(chan tracer.TargetSet, 1)
	targets <- tracer.TargetSet{
		{CgroupPath: "/real"},
		{CgroupPath: "", PodName: "ghost"}, // must be skipped
		{CgroupPath: ""},
	}
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, targets) }()

	waitUntil(t, 2*time.Second, func() bool { return eng.Stats().ActiveTargets == 1 })

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	if paths := backend.attachedPaths(); len(paths) != 1 || paths[0] != "/real" {
		t.Errorf("attached paths=%v, want [/real]", paths)
	}
}

// TestEngine_EmptyTargetSetIsNoOp asserts that an empty TargetSet does
// not crash applyTargets and does not bump any counters.
func TestEngine_EmptyTargetSetIsNoOp(t *testing.T) {
	backend := &mockBackend{}
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{&recordingExporter{name: "x"}}, tracer.Config{})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targets := make(chan tracer.TargetSet, 1)
	targets <- tracer.TargetSet{}

	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, targets) }()

	time.Sleep(50 * time.Millisecond)
	if s := eng.Stats(); s.ActiveTargets != 0 || s.ExporterFailure != 0 {
		t.Errorf("empty TargetSet disturbed stats: %+v", s)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// TestEngine_ConcurrentTargetUpdates is a smoke test for the race
// detector.
func TestEngine_ConcurrentTargetUpdates(t *testing.T) {
	backend := &mockBackend{}
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{&recordingExporter{name: "x"}}, tracer.Config{})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targets := make(chan tracer.TargetSet, 64)
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, targets) }()

	producers := 4
	perProducer := 25
	var wg sync.WaitGroup
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func(pid int) {
			defer wg.Done()
			for i := 0; i < perProducer; i++ {
				targets <- tracer.TargetSet{
					{CgroupPath: fmtPath(pid, i)},
					{CgroupPath: fmtPath(pid, i-1)},
				}
			}
		}(p)
	}
	wg.Wait()

	waitUntil(t, 3*time.Second, func() bool {
		return eng.Stats().CgroupsAttached >= int64(producers*perProducer/2)
	})

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func fmtPath(a, b int) string {
	return fmt.Sprintf("/c/%d/%d", a, b)
}

// TestEngine_EmptySnapshotDetachesAll asserts that an empty TargetSet
// arriving after a non-empty one fully detaches the previously active
// cgroups.
func TestEngine_EmptySnapshotDetachesAll(t *testing.T) {
	backend := &mockBackend{}
	exp := &recordingExporter{name: "x"}
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{exp}, tracer.Config{})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targets := make(chan tracer.TargetSet, 2)
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, targets) }()

	targets <- tracer.TargetSet{
		{CgroupPath: "/c/a"},
		{CgroupPath: "/c/b"},
	}
	waitUntil(t, 2*time.Second, func() bool { return eng.Stats().ActiveTargets == 2 })

	targets <- tracer.TargetSet{}
	waitUntil(t, 2*time.Second, func() bool { return eng.Stats().ActiveTargets == 0 })

	if active := backend.activePaths(); len(active) != 0 {
		t.Errorf("backend still has active paths after empty snapshot: %v", active)
	}
	if s := eng.Stats(); s.CgroupsDetached != 2 {
		t.Errorf("CgroupsDetached=%d, want 2", s.CgroupsDetached)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// TestEngine_PodRecreateRotatesCgroup simulates the pod delete-and-recreate
// scenario the user originally flagged: same pod name, different cgroup
// path.
func TestEngine_PodRecreateRotatesCgroup(t *testing.T) {
	backend := &mockBackend{}
	exp := &recordingExporter{name: "x"}
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{exp}, tracer.Config{})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targets := make(chan tracer.TargetSet, 2)
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, targets) }()

	targets <- tracer.TargetSet{
		{PodName: "web", CgroupPath: "/cg/pod-uid-1"},
	}
	waitUntil(t, 2*time.Second, func() bool { return eng.Stats().ActiveTargets == 1 })

	targets <- tracer.TargetSet{
		{PodName: "web", CgroupPath: "/cg/pod-uid-2"},
	}
	waitUntil(t, 2*time.Second, func() bool {
		ap := backend.activePaths()
		return len(ap) == 1 && ap[0] == "/cg/pod-uid-2"
	})

	if s := eng.Stats(); s.CgroupsAttached != 2 || s.CgroupsDetached != 1 {
		t.Errorf("attach/detach counters wrong: %+v", s)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// recordingObserver captures observer callbacks for assertion.
type recordingObserver struct {
	mu                sync.Mutex
	attachedTotal     int
	detachedTotal     int
	attachedCallbacks int
	detachedCallbacks int
}

func (r *recordingObserver) OnCgroupsAttached(n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.attachedTotal += n
	r.attachedCallbacks++
}

func (r *recordingObserver) OnCgroupsDetached(n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.detachedTotal += n
	r.detachedCallbacks++
}

func (r *recordingObserver) snapshot() (attachedTotal, detachedTotal, attachedCalls, detachedCalls int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.attachedTotal, r.detachedTotal, r.attachedCallbacks, r.detachedCallbacks
}

// TestEngine_ObserverNotifiedOnChurn asserts the optional EngineObserver
// is fed only when the active set actually changes.
func TestEngine_ObserverNotifiedOnChurn(t *testing.T) {
	backend := &mockBackend{}
	obs := &recordingObserver{}
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{&recordingExporter{name: "x"}}, tracer.Config{
		Observer: obs,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targets := make(chan tracer.TargetSet, 4)
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, targets) }()

	targets <- tracer.TargetSet{{CgroupPath: "/c/a"}, {CgroupPath: "/c/b"}}
	waitUntil(t, 2*time.Second, func() bool {
		a, _, _, _ := obs.snapshot()
		return a == 2
	})

	targets <- tracer.TargetSet{{CgroupPath: "/c/a"}, {CgroupPath: "/c/b"}}
	time.Sleep(50 * time.Millisecond)
	a, d, ac, dc := obs.snapshot()
	if a != 2 || d != 0 || ac != 1 || dc != 0 {
		t.Errorf("idempotent re-send disturbed observer: attached=%d detached=%d ac=%d dc=%d", a, d, ac, dc)
	}

	targets <- tracer.TargetSet{{CgroupPath: "/c/a"}, {CgroupPath: "/c/c"}}
	waitUntil(t, 2*time.Second, func() bool {
		_, dt, _, _ := obs.snapshot()
		return dt == 1
	})
	a, d, _, _ = obs.snapshot()
	if a != 3 || d != 1 {
		t.Errorf("after churn: attached=%d detached=%d, want 3/1", a, d)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// TestEngine_BackendSetCgroupsErrorPreservesActiveSet asserts that when
// SetCgroups fails, the engine does NOT clobber its previous active set
// the next snapshot retry can still converge.
func TestEngine_BackendSetCgroupsErrorPreservesActiveSet(t *testing.T) {
	backend := &mockBackend{}
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{&recordingExporter{name: "x"}}, tracer.Config{})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targets := make(chan tracer.TargetSet, 2)
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, targets) }()

	targets <- tracer.TargetSet{{CgroupPath: "/c/a"}, {CgroupPath: "/c/b"}}
	waitUntil(t, 2*time.Second, func() bool { return eng.Stats().ActiveTargets == 2 })

	backend.mu.Lock()
	backend.setCgroupsErr = errors.New("transient kernel hiccup")
	backend.mu.Unlock()

	targets <- tracer.TargetSet{{CgroupPath: "/c/c"}}
	waitUntil(t, 2*time.Second, func() bool { return eng.Stats().AttachFailure > 0 })

	if s := eng.Stats(); s.ActiveTargets != 2 {
		t.Errorf("ActiveTargets=%d after failed replace, want 2", s.ActiveTargets)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}
