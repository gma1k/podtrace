package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
)

func TestRowsTakenBeforeADrainFailureAreStillIngested(t *testing.T) {
	withKernelAggregation(t, true)
	prev := config.WorkloadMetricsDrainInterval
	config.WorkloadMetricsDrainInterval = 10 * time.Millisecond
	t.Cleanup(func() { config.WorkloadMetricsDrainInterval = prev })

	agg := &fakeAggregator{
		rows: []kernelagg.Row{{
			Key:   kernelagg.Key{CgroupID: 1, EventType: uint8(events.EventTCPSend), Bucket: 80},
			Value: kernelagg.Value{Count: 2, SumNS: 4000, Bytes: 700},
		}},
		drainErr: errors.New("take failed for 1 of 2 rows"),
		partial:  true,
	}
	metrics := NewMetrics()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- drainKernelMetrics(ctx, agg, kernelTestSink(t), nil, metrics, logr.Discard()) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && agg.drainCount() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("drain loop returned %v", err)
	}

	if got := testutil.ToFloat64(metrics.KernelAggRows.WithLabelValues("applied")); got == 0 {
		t.Error("rows already removed from the kernel map were dropped because another row failed")
	}
}
