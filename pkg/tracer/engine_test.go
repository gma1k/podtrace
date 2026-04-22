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
	mu          sync.Mutex
	attached    []string
	started     bool
	stopped     bool
	startErr    error
	attachErr   error
	setContainerErr error
	eventCh     chan<- *events.Event
}

func (m *mockBackend) AttachToCgroup(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.attachErr != nil {
		return m.attachErr
	}
	m.attached = append(m.attached, path)
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

func (m *mockBackend) attachedPaths() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.attached))
	copy(out, m.attached)
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
	waitUntil(t, 2*time.Second, func() bool { return len(backend.attachedPaths()) == 2 })

	// Add c, keep a; b removed — engine does not detach today (intra-run
	// detach is future work) so b stays attached. But c must be attached.
	targets <- tracer.TargetSet{
		{CgroupPath: "/sys/fs/cgroup/a", ContainerID: "a"},
		{CgroupPath: "/sys/fs/cgroup/c", ContainerID: "c"},
	}
	waitUntil(t, 2*time.Second, func() bool { return len(backend.attachedPaths()) == 3 })

	paths := backend.attachedPaths()
	want := map[string]bool{"/sys/fs/cgroup/a": true, "/sys/fs/cgroup/b": true, "/sys/fs/cgroup/c": true}
	for _, p := range paths {
		if !want[p] {
			t.Errorf("unexpected attached path %q", p)
		}
	}
	if len(paths) != 3 {
		t.Errorf("expected 3 attaches, got %d (%v)", len(paths), paths)
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

	// Emit 10 events; ExportBatchSize=4 means 2 full batches flush inline
	// and 2 events remain in the pending batch until shutdown flushes them.
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
// active target count. This is the metric surface agent mode will scrape
// for per-CR status reporting, so the contract matters.
func TestEngine_Stats(t *testing.T) {
	backend := &mockBackend{}
	exp := &recordingExporter{name: "rec"}
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{exp}, tracer.Config{EventBufferSize: 16, ExportBatchSize: 2})
	if err != nil {
		t.Fatal(err)
	}

	// Zero-state snapshot is all zeros.
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
// receives every batch. Agent mode will compose per-CR exporters behind
// the engine; a silent fan-out bug would mean one CR's exporter stops
// getting events.
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

	// Every exporter must have received identical event counts and been closed.
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
// ExporterFailure. Exporter outage must not tear down the tracer.
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
	// Good exporter still gets all events; bad one has failure count.
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

// TestEngine_AttachErrorDoesNotAbortRun ensures that a backend attach
// failure for one cgroup does not prevent the engine from processing
// later target sets (the error is tracked, not fatal).
func TestEngine_AttachErrorDoesNotAbortRun(t *testing.T) {
	backend := &mockBackend{attachErr: errors.New("attach broken")}
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

	// Recovery: clear the attach error and push a second snapshot. The
	// engine must still process it.
	waitUntil(t, 2*time.Second, func() bool { return eng.Stats().ExporterFailure > 0 })
	backend.mu.Lock()
	backend.attachErr = nil
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

	// Let it settle.
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
// detector. Run with `go test -race`; any data race in applyTargets'
// bookkeeping will fire.
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

	// Multiple producers hammer the engine with overlapping target sets.
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
		return eng.Stats().ActiveTargets >= producers*perProducer/2
	})

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func fmtPath(a, b int) string {
	return fmt.Sprintf("/c/%d/%d", a, b)
}
