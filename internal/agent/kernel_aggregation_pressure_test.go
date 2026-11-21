package agent

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
)

type pressureAggregator struct {
	*fakeAggregator
	mu       sync.Mutex
	pressure kernelagg.Pressure
	reads    int
}

func (p *pressureAggregator) KernelAggregationPressure() kernelagg.Pressure {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reads++
	return p.pressure
}

func (p *pressureAggregator) readCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.reads
}

func TestKernelAggPressureCountsOnlyTheGrowth(t *testing.T) {
	m := NewMetrics()

	m.RecordKernelAggPressure(kernelagg.Pressure{RowsEvicted: 5, PeerCollapsed: 2})
	m.RecordKernelAggPressure(kernelagg.Pressure{RowsEvicted: 5, PeerCollapsed: 9})
	m.RecordKernelAggPressure(kernelagg.Pressure{RowsEvicted: 8, PeerCollapsed: 9})

	if got := testutil.ToFloat64(m.KernelAggRows.WithLabelValues("evicted")); got != 8 {
		t.Errorf("evicted = %v, want 8", got)
	}
	if got := testutil.ToFloat64(m.KernelAggRows.WithLabelValues("peer_collapsed")); got != 9 {
		t.Errorf("peer_collapsed = %v, want 9", got)
	}
}

func TestKernelAggPressureIgnoresANilMetrics(t *testing.T) {
	var m *Metrics
	m.RecordKernelAggPressure(kernelagg.Pressure{RowsEvicted: 1})
	(&Metrics{}).RecordKernelAggPressure(kernelagg.Pressure{RowsEvicted: 1})
}

func TestAnAggregatorWithoutPressureReportingIsSkipped(t *testing.T) {
	m := NewMetrics()
	recordKernelAggPressure(&fakeAggregator{}, m)
	if got := testutil.CollectAndCount(m.KernelAggRows); got != 0 {
		t.Errorf("%d series recorded for an aggregator that reports no pressure", got)
	}
}

func TestTheDrainLoopPublishesKernelAggPressure(t *testing.T) {
	withKernelAggregation(t, true)
	prev := config.WorkloadMetricsDrainInterval
	config.WorkloadMetricsDrainInterval = 10 * time.Millisecond
	t.Cleanup(func() { config.WorkloadMetricsDrainInterval = prev })

	agg := &pressureAggregator{
		fakeAggregator: &fakeAggregator{},
		pressure:       kernelagg.Pressure{RowsEvicted: 4, PeerCollapsed: 6},
	}
	metrics := NewMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- drainKernelMetrics(ctx, agg, kernelTestSink(t), NewRouter(nil), metrics, logr.Discard())
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && agg.readCount() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("drain loop returned %v", err)
	}

	if got := testutil.ToFloat64(metrics.KernelAggRows.WithLabelValues("evicted")); got != 4 {
		t.Errorf("evicted = %v, want 4", got)
	}
	if got := testutil.ToFloat64(metrics.KernelAggRows.WithLabelValues("peer_collapsed")); got != 6 {
		t.Errorf("peer_collapsed = %v, want 6", got)
	}
}
