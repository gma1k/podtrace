package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
)

func TestKernelAggregationModeKeepsL7ResponsesForSemanticConventions(t *testing.T) {
	for _, tc := range []struct {
		hasRules, semanticConventions bool
		want                          kernelagg.Mode
	}{
		{true, false, kernelagg.ModeOn},
		{true, true, kernelagg.ModeOn},
		{false, false, kernelagg.ModeBypass},
		{false, true, kernelagg.ModeBypassExceptL7},
	} {
		if got := kernelAggregationMode(tc.hasRules, tc.semanticConventions); got != tc.want {
			t.Errorf("kernelAggregationMode(rules=%v, semconv=%v) = %s, want %s",
				tc.hasRules, tc.semanticConventions, got, tc.want)
		}
	}
}

func TestTheDrainLoopArmsTheL7PassThroughWhenSemanticConventionsAreOn(t *testing.T) {
	withKernelAggregation(t, true)
	prevInterval, prevSemconv := config.WorkloadMetricsDrainInterval, config.WorkloadMetricsSemanticConv
	config.WorkloadMetricsDrainInterval = time.Hour
	config.WorkloadMetricsSemanticConv = true
	t.Cleanup(func() {
		config.WorkloadMetricsDrainInterval = prevInterval
		config.WorkloadMetricsSemanticConv = prevSemconv
	})

	agg := &fakeAggregator{}
	router := NewRouter(nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- drainKernelMetrics(ctx, agg, kernelTestSink(t), router, NewMetrics(), logr.Discard()) }()

	armed := func(want kernelagg.Mode) bool {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			for _, m := range agg.modeLog() {
				if m == want {
					return true
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
		return false
	}
	if !armed(kernelagg.ModeBypassExceptL7) {
		t.Errorf("modes = %v; with semantic conventions on and no CR routing, the served L7 "+
			"responses must keep reaching the plane", agg.modeLog())
	}
	router.Publish([]CRRule{{Key: CRKey{Name: "cr"}}}).Wait()
	if !armed(kernelagg.ModeOn) {
		t.Errorf("modes = %v; publishing a CR never lifted the bypass", agg.modeLog())
	}
	for _, m := range agg.modeLog() {
		if m == kernelagg.ModeBypass {
			t.Errorf("modes = %v; the full bypass was armed although semantic conventions are on", agg.modeLog())
			break
		}
	}

	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Errorf("drainKernelMetrics returned %v on shutdown", err)
	}
}
