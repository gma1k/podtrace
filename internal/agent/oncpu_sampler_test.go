package agent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/gma1k/podtrace/internal/ebpf/oncpu"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/profiling"
	"github.com/gma1k/podtrace/pkg/tracer"
)

type fakeOnCPUSampler struct {
	*NoopBackend
	mu       sync.Mutex
	startErr error
	drainErr error
	drained  oncpu.Drained
	drains   int
}

func (f *fakeOnCPUSampler) StartOnCPUSampler() (int, error) {
	if f.startErr != nil {
		return 0, f.startErr
	}
	return 4, nil
}

func (f *fakeOnCPUSampler) DrainOnCPUSamples() (oncpu.Drained, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.drains++
	if f.drainErr != nil {
		return oncpu.Drained{}, f.drainErr
	}
	d := f.drained
	f.drained = oncpu.Drained{}
	return d, nil
}

func (f *fakeOnCPUSampler) drainCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.drains
}

func fastOnCPUDrains(t *testing.T) {
	t.Helper()
	orig := onCPUDrainInterval
	onCPUDrainInterval = 5 * time.Millisecond
	t.Cleanup(func() { onCPUDrainInterval = orig })
}

func checkoutProfiler() *profiling.ContinuousProfiler {
	return profiling.NewContinuousProfiler(nil, func(uint64) (events.K8sMetadata, bool) {
		return events.K8sMetadata{Namespace: "shop", WorkloadName: "checkout"}, true
	})
}

func runOnCPUDrain(t *testing.T, backend tracer.TracerBackend, profiler *profiling.ContinuousProfiler, metrics *Metrics, until func() bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- drainOnCPUSamples(ctx, backend, profiler, metrics, logr.Discard()) }()
	deadline := time.Now().Add(5 * time.Second)
	for !until() && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("drainOnCPUSamples = %v", err)
	}
}

func TestTheOnCPUSamplerFeedsTheProfiler(t *testing.T) {
	fastOnCPUDrains(t)
	f := &fakeOnCPUSampler{NoopBackend: NewNoopBackend(), drained: oncpu.Drained{
		Samples:    []oncpu.Sample{{CgroupID: 1, PID: 1, Stack: []uint64{0xbeef}, Count: 9}},
		Lost:       [2]uint64{2, 1},
		Unresolved: 3,
	}}
	p := checkoutProfiler()
	m := NewMetrics()
	runOnCPUDrain(t, f, p, m, func() bool { return f.drainCount() >= 2 })

	if p.Source() != profiling.SourceOnCPU {
		t.Errorf("source = %q", p.Source())
	}
	if got := p.Snapshot(context.Background()); len(got) != 1 || got[0].Samples != 9 {
		t.Errorf("profile = %+v", got)
	}
	if testutil.ToFloat64(m.OnCPUSamplerCPUs) != 4 || testutil.ToFloat64(m.OnCPUSamples) != 9 {
		t.Errorf("cpus = %v, samples = %v", testutil.ToFloat64(m.OnCPUSamplerCPUs), testutil.ToFloat64(m.OnCPUSamples))
	}
	for reason, want := range map[string]float64{"stack_unavailable": 2, "count_map_full": 1, "stack_evicted": 3} {
		if got := testutil.ToFloat64(m.OnCPUSamplesLost.WithLabelValues(reason)); got != want {
			t.Errorf("lost{%s} = %v, want %v", reason, got, want)
		}
	}
}

func TestAFailedOnCPUDrainIsCounted(t *testing.T) {
	fastOnCPUDrains(t)
	f := &fakeOnCPUSampler{NoopBackend: NewNoopBackend(), drainErr: errors.New("map gone")}
	m := NewMetrics()
	runOnCPUDrain(t, f, checkoutProfiler(), m, func() bool { return f.drainCount() >= 1 })
	if testutil.ToFloat64(m.OnCPUDrainFailures) < 1 {
		t.Error("a failed drain was not counted")
	}
}

func TestTheProfilerStaysOnSchedSwitchWhenTheSamplerCannotStart(t *testing.T) {
	m := NewMetrics()
	p := checkoutProfiler()
	f := &fakeOnCPUSampler{NoopBackend: NewNoopBackend(), startErr: errors.New("perf_event_open: EACCES")}
	if err := drainOnCPUSamples(context.Background(), f, p, m, logr.Discard()); err != nil {
		t.Fatal(err)
	}
	if p.Source() != profiling.SourceSchedSwitch || testutil.ToFloat64(m.OnCPUSamplerCPUs) != 0 {
		t.Errorf("source = %q", p.Source())
	}
	if err := drainOnCPUSamples(context.Background(), NewNoopBackend(), p, m, logr.Discard()); err != nil {
		t.Errorf("a backend without the sampler = %v", err)
	}
	if err := drainOnCPUSamples(context.Background(), f, nil, m, logr.Discard()); err != nil {
		t.Errorf("no profiler = %v", err)
	}
}

func TestTheOnCPUMetricsAreSafeWhenNil(t *testing.T) {
	var m *Metrics
	m.RecordOnCPUSampler(1)
	m.RecordOnCPUDrain(oncpu.Drained{})
	m.RecordOnCPUDrainFailure()
}
