package tracer_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/gma1k/podtrace/pkg/tracer"
)

type dropReportingBackend struct {
	*mockBackend
	reporter func(string, int)
}

func (b *dropReportingBackend) SetDropReporter(r func(reason string, n int)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reporter = r
}

func (b *dropReportingBackend) getReporter() func(string, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.reporter
}

type recordingDropObserver struct {
	mu     sync.Mutex
	reason string
	n      int
	calls  int
}

func (o *recordingDropObserver) OnCgroupsAttached(int) {}
func (o *recordingDropObserver) OnCgroupsDetached(int) {}
func (o *recordingDropObserver) OnEventsDropped(reason string, n int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.reason = reason
	o.n += n
	o.calls++
}

func TestEngine_WiresDropReporterToObserver(t *testing.T) {
	backend := &dropReportingBackend{mockBackend: &mockBackend{}}
	obs := &recordingDropObserver{}
	exp := &recordingExporter{name: "x"}
	eng, err := tracer.NewEngine(backend, []tracer.Exporter{exp}, tracer.Config{
		EventBufferSize: 16,
		ExportBatchSize: 4,
		Observer:        obs,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	targets := make(chan tracer.TargetSet, 1)
	targets <- tracer.TargetSet{{CgroupPath: "/c"}}
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, targets) }()

	waitUntil(t, 2*time.Second, func() bool { return backend.getReporter() != nil })
	backend.getReporter()("channel_full", 4)

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}

	obs.mu.Lock()
	defer obs.mu.Unlock()
	if obs.calls != 1 || obs.reason != "channel_full" || obs.n != 4 {
		t.Fatalf("observer got reason=%q n=%d calls=%d, want channel_full/4/1", obs.reason, obs.n, obs.calls)
	}
}
