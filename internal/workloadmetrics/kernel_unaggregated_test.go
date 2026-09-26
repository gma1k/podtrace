package workloadmetrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
)

var checkoutBase = []string{"shop", "checkout", "Deployment", "app"}

func sampleCount(t *testing.T, sink *Sink, family string) uint64 {
	t.Helper()
	var total uint64
	for _, m := range gather(t, sink.own, metricPrefix+family) {
		total += m.GetHistogram().GetSampleCount()
	}
	return total
}

func TestUnaggregatedProbesStillReachKernelOwnedFamilies(t *testing.T) {
	for _, tc := range []struct {
		name   string
		event  events.Event
		family string
	}{
		{"off-CPU time", events.Event{Type: events.EventSchedSwitch, LatencyNS: 3_000_000}, "cpu_blocked_seconds"},
		{"run-queue wait", events.Event{Type: events.EventSchedSwitch, LatencyNS: 3_000_000, TCPState: schedPreempted}, "cpu_runqueue_latency_seconds"},
		{"lock wait", events.Event{Type: events.EventLockContention, LatencyNS: 2_000_000}, "lock_contention_seconds"},
		{"file open", events.Event{Type: events.EventOpen, LatencyNS: 1_500_000}, "filesystem_latency_seconds"},
		{"redis command", events.Event{Type: events.EventRedisCmd, LatencyNS: 1_000_000}, "l7_request_duration_seconds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink, _ := kernelSink(t)
			e := tc.event
			e.CgroupID = kernelTestCgroup
			sink.record(&e, checkoutBase)

			if got := sampleCount(t, sink, tc.family); got != 1 {
				t.Errorf("%s has %d samples, want 1.\n\nThis probe writes to the ring buffer "+
					"without aggregating in the kernel. With kernel aggregation on, the event "+
					"path used to skip every family the kernel owns, so observations like this "+
					"one reached neither path: on kind cpu_runqueue_latency_seconds was empty "+
					"and cpu.contention never fired for a CPU-throttled pod.", tc.family, got)
			}
		})
	}
}

func TestAnAggregatedAndAnUnaggregatedObservationShareOneSeries(t *testing.T) {
	sink, reg := kernelSink(t)
	sink.IngestKernel([]kernelagg.Row{
		kernelRow(events.EventSchedSwitch, 0, kernelagg.BucketIndex(3_000_000), 4, 12_000_000, 0),
	})
	sink.record(&events.Event{
		Type: events.EventSchedSwitch, CgroupID: kernelTestCgroup, LatencyNS: 3_000_000,
	}, checkoutBase)

	metrics := gather(t, reg, "podtrace_workload_cpu_blocked_seconds")
	if len(metrics) != 1 {
		t.Fatalf("got %d cpu_blocked series, want one: both sources describe the same workload", len(metrics))
	}
	if got := metrics[0].GetHistogram().GetSampleCount(); got != 5 {
		t.Errorf("sample count = %d, want 5: four from the kernel map and one from the ring buffer", got)
	}
	if got := metrics[0].GetHistogram().GetSampleSum(); got < 0.0149 || got > 0.0151 {
		t.Errorf("sample sum = %v, want 0.015s", got)
	}
}

func TestAKernelCountedEventIsNotCountedAgainForAnyFamily(t *testing.T) {
	sink, _ := kernelSink(t)
	for _, typ := range []events.EventType{events.EventSchedSwitch, events.EventLockContention, events.EventOpen, events.EventRedisCmd} {
		sink.record(&events.Event{
			Type: typ, CgroupID: kernelTestCgroup, LatencyNS: 2_000_000, KernelAggregated: true,
		}, checkoutBase)
	}
	for _, family := range []string{"cpu_blocked_seconds", "lock_contention_seconds", "filesystem_latency_seconds", "l7_request_duration_seconds"} {
		if got := sampleCount(t, sink, family); got != 0 {
			t.Errorf("%s counted %d samples from events the kernel already aggregated", family, got)
		}
	}
}

func TestAZeroLatencyUnaggregatedObservationLandsInTheLowestBucket(t *testing.T) {
	sink, _ := kernelSink(t)
	sink.record(&events.Event{Type: events.EventSchedSwitch, CgroupID: kernelTestCgroup}, checkoutBase)
	if got := sampleCount(t, sink, "cpu_blocked_seconds"); got != 1 {
		t.Errorf("a zero-latency observation was lost (count %d)", got)
	}
}

func TestAnUnaggregatedObservationRespectsTheSeriesBudget(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{
		NativeHistograms:  true,
		KernelAggregation: true,
		Lookup:            kernelTestLookup,
		SeriesBudget:      1,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sink.record(&events.Event{Type: events.EventLockContention, CgroupID: kernelTestCgroup, LatencyNS: 2_000_000}, checkoutBase)
	sink.record(&events.Event{Type: events.EventSchedSwitch, CgroupID: kernelTestCgroup, LatencyNS: 2_000_000}, checkoutBase)

	if got := sampleCount(t, sink, "cpu_blocked_seconds"); got != 0 {
		t.Errorf("cpu_blocked_seconds took %d samples past a spent budget of 1 series; the "+
			"kernel-store path must be bounded by the same cap as every other", got)
	}
	if got := sampleCount(t, sink, "lock_contention_seconds"); got != 1 {
		t.Errorf("the series admitted within budget has %d samples, want 1", got)
	}
}
