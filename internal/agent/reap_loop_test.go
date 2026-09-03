package agent

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/workloadmetrics"
)

func reapedTotal(t *testing.T, reg *prometheus.Registry) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != "podtrace_workload_metrics_series_reaped_total" {
			continue
		}
		var total float64
		for _, m := range f.GetMetric() {
			total += m.GetCounter().GetValue()
		}
		return total
	}
	return 0
}

func dnsSeriesCount(t *testing.T, reg *prometheus.Registry) int {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() == "podtrace_workload_dns_latency_seconds" && f.GetType() == dto.MetricType_HISTOGRAM {
			return len(f.GetMetric())
		}
	}
	return 0
}

func TestReapLoopEvictsIdleSeriesOnItsInterval(t *testing.T) {
	originalInterval := config.WorkloadMetricsReapInterval
	originalTTL := config.WorkloadMetricsSeriesTTL
	config.WorkloadMetricsReapInterval = 10 * time.Millisecond
	config.WorkloadMetricsSeriesTTL = time.Nanosecond
	t.Cleanup(func() {
		config.WorkloadMetricsReapInterval = originalInterval
		config.WorkloadMetricsSeriesTTL = originalTTL
	})

	reg := prometheus.NewRegistry()
	sink, err := workloadmetrics.New(reg, workloadmetrics.Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := sink.Export(context.Background(), []*events.Event{{
		Type:      events.EventDNS,
		LatencyNS: 1_000_000,
		K8s: &events.K8sMetadata{
			Namespace:    "shop",
			WorkloadName: "checkout",
		},
	}}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if dnsSeriesCount(t, reg) != 1 {
		t.Fatalf("want 1 series before reaping, got %d", dnsSeriesCount(t, reg))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- reapWorkloadMetrics(ctx, sink, logr.Discard()) }()

	deadline := time.After(5 * time.Second)
	for reapedTotal(t, reg) == 0 {
		select {
		case <-deadline:
			t.Fatal("the reap loop never evicted the idle series; without it the plane " +
				"leaks and the per-node budget is eventually spent on dead workloads")
		case <-time.After(10 * time.Millisecond):
		}
	}

	if got := dnsSeriesCount(t, reg); got != 0 {
		t.Errorf("%d series survived the loop", got)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("reapWorkloadMetrics returned %v on cancellation, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("reapWorkloadMetrics did not return on context cancellation; it would " +
			"block the agent's errgroup on shutdown")
	}
}

func TestReapLoopIsANoOpWithoutASink(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := reapWorkloadMetrics(ctx, nil, logr.Discard()); err != nil {
		t.Errorf("got %v, want nil; the loop must be inert when the plane is disabled", err)
	}
}
