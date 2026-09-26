package workloadmetrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/diagnose/detector"
	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
	"github.com/gma1k/podtrace/internal/inspect"
)

func rttRows(latencyNS uint64, count uint64) []kernelagg.Row {
	return []kernelagg.Row{
		kernelRow(events.EventTCPRTT, 0, kernelagg.BucketIndex(latencyNS), count, latencyNS*count, 0),
	}
}

func evaluateOverKernelRows(t *testing.T, first, second []kernelagg.Row) []detector.Issue {
	t.Helper()
	sink, _ := kernelSink(t)
	clock := time.Now()
	engine, err := inspect.New(inspect.Options{
		Source:     sink,
		Registerer: prometheus.NewRegistry(),
		Thresholds: inspect.DefaultThresholds(),
		Now:        func() time.Time { return clock },
	})
	if err != nil {
		t.Fatalf("inspect.New: %v", err)
	}

	var active []detector.Issue
	for i := 0; i < 12; i++ {
		rows := second
		if i == 0 {
			rows = first
		}
		sink.IngestKernel(rows)
		if _, err := engine.Evaluate(); err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		clock = clock.Add(30 * time.Second)
		active = engine.Active()
	}
	return active
}

func hasIssue(issues []detector.Issue, id detector.ID) bool {
	for _, i := range issues {
		if i.ID == id {
			return true
		}
	}
	return false
}

func TestAKernelAggregatedRTTSpikeRaisesTheIssue(t *testing.T) {
	active := evaluateOverKernelRows(t, rttRows(150_000_000, 50), rttRows(150_000_000, 50))
	if !hasIssue(active, detector.IDRTTSpikeRate) {
		t.Errorf("no net.rtt_spike_rate with every RTT at 150ms against a 100ms bound; got %v.\n\n"+
			"Kernel-aggregated families are native histograms with no classic buckets, and "+
			"the rule needs bucket counts to know what share was slow. On kind this is why "+
			"a workload behind 150ms of netem never raised the issue whenever kernel "+
			"aggregation was on.", active)
	}
}

func TestAFastKernelAggregatedRTTStaysQuiet(t *testing.T) {
	active := evaluateOverKernelRows(t, rttRows(300_000, 50), rttRows(300_000, 50))
	if hasIssue(active, detector.IDRTTSpikeRate) {
		t.Errorf("net.rtt_spike_rate fired on a 0.3ms RTT: %v", active)
	}
}
