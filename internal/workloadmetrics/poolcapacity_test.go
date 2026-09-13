package workloadmetrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/events"
)

func poolStatsEvent(pod string, numOpen uint64, maxOpen uint32, percent int32) *events.Event {
	return &events.Event{
		Type:     events.EventDBPoolStats,
		Error:    percent,
		Bytes:    numOpen,
		TCPState: maxOpen,
		K8s:      replica(pod),
	}
}

func gaugeValue(t *testing.T, reg *prometheus.Registry, name string) (float64, bool) {
	t.Helper()
	metrics := gather(t, reg, name)
	if len(metrics) == 0 {
		return 0, false
	}
	if len(metrics) != 1 {
		t.Fatalf("%s: got %d series, want 1", name, len(metrics))
	}
	return metrics[0].GetGauge().GetValue(), true
}

func TestPoolCapacityReportsBothOpenConnectionsAndUtilization(t *testing.T) {
	sink, reg := newTestSink(t, 0)
	exportAll(t, sink, poolStatsEvent("checkout-a", 18, 20, 90))

	if got, ok := gaugeValue(t, reg, "podtrace_workload_db_pool_connections_open"); !ok || got != 18 {
		t.Errorf("connections open = %v (present=%v), want 18", got, ok)
	}
	if got, ok := gaugeValue(t, reg, "podtrace_workload_db_pool_utilization_percent"); !ok || got != 90 {
		t.Errorf("utilization = %v (present=%v), want 90", got, ok)
	}
}

func TestAnUnlimitedPoolReportsItsCountButNoPercentage(t *testing.T) {
	sink, reg := newTestSink(t, 0)
	exportAll(t, sink, poolStatsEvent("checkout-a", 37, 0, 0))

	if got, ok := gaugeValue(t, reg, "podtrace_workload_db_pool_connections_open"); !ok || got != 37 {
		t.Errorf("connections open = %v (present=%v), want 37; an unlimited pool is exactly "+
			"where a growing count is the leak signal", got, ok)
	}
	if got, ok := gaugeValue(t, reg, "podtrace_workload_db_pool_utilization_percent"); ok {
		t.Errorf("utilization = %v was reported for a pool with no maximum; 0%% reads as an "+
			"idle pool rather than an unbounded one", got)
	}
}

func TestABusyPoolIsNotHiddenByAnIdleReplica(t *testing.T) {
	sink, reg := newTestSink(t, 0)
	exportAll(t, sink,
		poolStatsEvent("checkout-hot", 19, 20, 95),
		poolStatsEvent("checkout-cold", 1, 20, 5),
	)

	if got, _ := gaugeValue(t, reg, "podtrace_workload_db_pool_utilization_percent"); got != 95 {
		t.Errorf("utilization = %v, want the held peak 95; the pod label is off by default, "+
			"so both replicas write this series and the idle one erased the saturated one", got)
	}
	if got, _ := gaugeValue(t, reg, "podtrace_workload_db_pool_connections_open"); got != 19 {
		t.Errorf("connections open = %v, want 19; a held 95%% beside a current 1 connection "+
			"puts two different moments of the same pool on one dashboard", got)
	}
}

func TestAPoolPeakDecaysSoARecoveredPoolIsVisible(t *testing.T) {
	clock := time.Now()
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	exportAll(t, sink, poolStatsEvent("checkout-a", 20, 20, 100))
	exportAll(t, sink, poolStatsEvent("checkout-a", 2, 20, 10))
	if got, _ := gaugeValue(t, reg, "podtrace_workload_db_pool_utilization_percent"); got != 100 {
		t.Fatalf("utilization = %v inside the hold window, want the peak 100", got)
	}

	clock = clock.Add(utilizationHoldWindow + time.Second)
	exportAll(t, sink, poolStatsEvent("checkout-a", 2, 20, 10))
	if got, _ := gaugeValue(t, reg, "podtrace_workload_db_pool_utilization_percent"); got != 10 {
		t.Errorf("utilization = %v after the hold window, want 10; a peak held forever pins "+
			"a resized pool at its worst reading", got)
	}
}

func TestAPoolSampleIsNeverCountedAsAnError(t *testing.T) {
	sink, reg := newTestSink(t, 0)
	exportAll(t, sink, poolStatsEvent("checkout-a", 18, 20, 90))

	if metrics := gather(t, reg, "podtrace_workload_errors_total"); len(metrics) != 0 {
		t.Errorf("a pool sample raised errors_total: %v.\n\nThe utilization percentage "+
			"travels in Event.Error, so every pool above 0%% would be reported as a failure "+
			"here and everywhere else IsError is consulted", labelsOf(metrics[0]))
	}
}

func TestANegativePoolUtilizationIsNotReported(t *testing.T) {
	sink, reg := newTestSink(t, 0)
	exportAll(t, sink, poolStatsEvent("checkout-a", 5, 20, -1))

	for _, name := range []string{
		"podtrace_workload_db_pool_connections_open",
		"podtrace_workload_db_pool_utilization_percent",
	} {
		if metrics := gather(t, reg, name); len(metrics) != 0 {
			t.Errorf("%s was reported from a negative sample: %v", name, metrics)
		}
	}
}

func TestAnImplausibleConnectionCountIsDropped(t *testing.T) {
	sink, reg := newTestSink(t, 0)
	exportAll(t, sink, poolStatsEvent("checkout-a", maxPlausiblePoolConnections+1, 20, 90))

	for _, name := range []string{
		"podtrace_workload_db_pool_connections_open",
		"podtrace_workload_db_pool_utilization_percent",
	} {
		if metrics := gather(t, reg, name); len(metrics) != 0 {
			t.Errorf("%s was reported from a count no pool can hold: %v.\n\nA reading that "+
				"large means the struct offsets are not describing database/sql.DB", name, metrics)
		}
	}
}

func TestPoolCapacitySeriesAreReapedWithTheirWorkload(t *testing.T) {
	clock := time.Now()
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	exportAll(t, sink, poolStatsEvent("checkout-a", 18, 20, 90))
	clock = clock.Add(20 * time.Minute)
	if n := sink.Reap(15 * time.Minute); n != 2 {
		t.Fatalf("Reap removed %d series, want 2; a gauge the reaper cannot resolve keeps "+
			"reporting a departed workload as saturated forever", n)
	}

	for _, name := range []string{
		"podtrace_workload_db_pool_connections_open",
		"podtrace_workload_db_pool_utilization_percent",
	} {
		if metrics := gather(t, reg, name); len(metrics) != 0 {
			t.Errorf("%s survived the reaper: %v", name, metrics)
		}
	}
}

func TestPoolCapacityCarriesNoPodLabelUnlessOptedIn(t *testing.T) {
	sink, reg := newTestSink(t, 0)
	exportAll(t, sink, poolStatsEvent("checkout-a", 18, 20, 90))

	for _, name := range []string{
		"podtrace_workload_db_pool_connections_open",
		"podtrace_workload_db_pool_utilization_percent",
	} {
		for _, m := range gather(t, reg, name) {
			if _, present := labelsOf(m)["pod"]; present {
				t.Errorf("%s carries a pod label without being opted in: %v", name, labelsOf(m))
			}
		}
	}
}
