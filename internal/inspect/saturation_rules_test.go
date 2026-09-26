package inspect

import (
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/diagnose/detector"
)

func poolAt(pct float64) []*dto.MetricFamily {
	return []*dto.MetricFamily{
		gaugeFamily(familyPoolUtilization, gauge(pct, workloadLabels()...)),
	}
}

func TestPoolSaturationFiresAsAWarningAtTheWarnBand(t *testing.T) {
	got := evalOnce(t, poolSaturationRule(), nil, poolAt(85), time.Minute)
	if len(got) != 1 {
		t.Fatalf("expected one issue at 85%% pool utilization, got %d", len(got))
	}
	if got[0].ID != detector.IDDBPoolSaturated {
		t.Errorf("wrong id: %q", got[0].ID)
	}
	if got[0].Severity != alerting.SeverityWarning {
		t.Errorf("expected warning at 85%%, got %q", got[0].Severity)
	}
}

func TestPoolSaturationEscalatesAtTheCriticalBand(t *testing.T) {
	got := evalOnce(t, poolSaturationRule(), nil, poolAt(95), time.Minute)
	if len(got) != 1 {
		t.Fatalf("expected one issue at 95%% pool utilization, got %d", len(got))
	}
	if got[0].Severity != alerting.SeverityCritical {
		t.Errorf("expected critical at 95%%, got %q", got[0].Severity)
	}
}

func TestPoolSaturationStaysQuietBelowTheWarnBand(t *testing.T) {
	if got := evalOnce(t, poolSaturationRule(), nil, poolAt(79), time.Minute); len(got) != 0 {
		t.Errorf("fired at 79%% against an 80%% warning band: %v", got)
	}
}

func TestPoolSaturationFiresBeforeAcquisitionsSlowDown(t *testing.T) {
	got := evalOnce(t, poolSaturationRule(), nil, poolAt(90), time.Minute)
	if len(got) != 1 {
		t.Fatalf("expected one issue, got %d", len(got))
	}
	acquire := evalOnce(t, acquireLatencyRule(), nil, []*dto.MetricFamily{
		histogramFamily(familyAcquire, histogram(1000, 1, workloadLabels()...)),
	}, time.Minute)
	if len(acquire) != 0 {
		t.Fatalf("the fixture was meant to have fast acquisitions: %v", acquire)
	}
}

func blocked(count uint64, sum float64) *dto.MetricFamily {
	return histogramFamily(familyCPURunqueue, histogram(count, sum, workloadLabels()...))
}

func offCPUOnly(count uint64, sum float64) *dto.MetricFamily {
	return histogramFamily("podtrace_workload_cpu_blocked_seconds", histogram(count, sum, workloadLabels()...))
}

func lockWaits(count uint64, sum float64) *dto.MetricFamily {
	return histogramFamily(familyLockContention, histogram(count, sum, workloadLabels()...))
}

func TestCPUContentionFiresOnTimeSpentOffCPU(t *testing.T) {
	got := evalOnce(t, cpuContentionRule(), nil,
		[]*dto.MetricFamily{blocked(100, 100)}, time.Minute)
	if len(got) != 1 {
		t.Fatalf("expected one issue at a 1s mean off-CPU, got %d", len(got))
	}
	if got[0].ID != detector.IDCPUContention {
		t.Errorf("wrong id: %q", got[0].ID)
	}
}

func TestCPUContentionStaysQuietBelowTheThreshold(t *testing.T) {
	got := evalOnce(t, cpuContentionRule(), nil,
		[]*dto.MetricFamily{blocked(1000, 2)}, time.Minute)
	if len(got) != 0 {
		t.Errorf("fired at a 2ms mean against a 50ms threshold: %v", got)
	}
}

func TestCPUContentionBlamesTheSchedulerWhenLockWaitsAreShorter(t *testing.T) {
	got := evalOnce(t, cpuContentionRule(), nil,
		[]*dto.MetricFamily{blocked(100, 100), lockWaits(100, 1)}, time.Minute)
	if len(got) != 1 {
		t.Fatalf("expected one issue, got %d", len(got))
	}
	if !strings.Contains(got[0].Remediation, "no CPU to run on") {
		t.Errorf("expected the scheduler remediation, got: %q", got[0].Remediation)
	}
}

func TestCPUContentionBlamesLocksWhenLockWaitsAreLonger(t *testing.T) {
	got := evalOnce(t, cpuContentionRule(), nil,
		[]*dto.MetricFamily{blocked(100, 100), lockWaits(100, 200)}, time.Minute)
	if len(got) != 1 {
		t.Fatalf("expected one issue, got %d", len(got))
	}
	if !strings.Contains(got[0].Remediation, "contention inside the application") {
		t.Errorf("expected the lock remediation, got: %q", got[0].Remediation)
	}
}

func TestCPUContentionCarriesLockWaitsAsEvidence(t *testing.T) {
	got := evalOnce(t, cpuContentionRule(), nil,
		[]*dto.MetricFamily{blocked(100, 100), lockWaits(100, 200)}, time.Minute)
	if len(got) != 1 {
		t.Fatalf("expected one issue, got %d", len(got))
	}
	var found bool
	for _, e := range got[0].Evidence {
		if e.Name == "mean_lock_wait" {
			found = true
		}
	}
	if !found {
		t.Errorf("lock waits were not attached as evidence: %+v", got[0].Evidence)
	}
}

func TestPoolSaturationStaysSilentWhenItsBandIsUnset(t *testing.T) {
	start := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	cur, err := Take(&fixedGatherer{families: poolAt(100)}, start)
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	window := Window{Prev: cur, Cur: cur}

	got := poolSaturationRule().Eval(window, Thresholds{})
	if len(got) != 0 {
		t.Errorf("a zero warning band fired on every pool: %v.\n\nThresholds.unset() only "+
			"backfills when every field is zero, so one unset field reaches the rule as "+
			"zero and >= 0 matches everything.", got)
	}
}

func TestCPUContentionSkipsASeriesWithNoObservationsInTheWindow(t *testing.T) {
	cur := []*dto.MetricFamily{blocked(0, 0)}
	if got := evalOnce(t, cpuContentionRule(), nil, cur, time.Minute); len(got) != 0 {
		t.Errorf("a histogram with no observations produced an issue: %v", got)
	}
}

func TestCPUContentionIgnoresASeriesThatReset(t *testing.T) {
	prev := []*dto.MetricFamily{blocked(1000, 500)}
	cur := []*dto.MetricFamily{blocked(10, 5)}

	if got := evalOnce(t, cpuContentionRule(), prev, cur, time.Minute); len(got) != 0 {
		t.Errorf("a counter reset was read as contention: %v", got)
	}
}

func TestCPUContentionIgnoresVoluntarilySleepingWorkloads(t *testing.T) {
	cur := []*dto.MetricFamily{offCPUOnly(100, 282)}

	if got := evalOnce(t, cpuContentionRule(), nil, cur, time.Minute); len(got) != 0 {
		t.Errorf("fired on a 2820ms mean off-CPU with no preemptions: %v.\n\nThat is the "+
			"shape of an idle pod parked in epoll_wait. Reading cpu_blocked_seconds made "+
			"this rule fire on every idle workload on the node and stay silent on the "+
			"busy ones.", got)
	}
}

func TestCPUContentionReportsPreemptionsNotSleep(t *testing.T) {
	got := evalOnce(t, cpuContentionRule(), nil,
		[]*dto.MetricFamily{blocked(100, 100), offCPUOnly(100, 282)}, time.Minute)
	if len(got) != 1 {
		t.Fatalf("expected one issue from a 1s mean run-queue latency, got %d", len(got))
	}
	if !strings.Contains(got[0].Message, "runnable but not running") {
		t.Errorf("message does not say what was measured: %q", got[0].Message)
	}
	for _, e := range got[0].Evidence {
		if e.Name == "mean_off_cpu" {
			t.Error("evidence still reports mean_off_cpu, which is not what the rule reads")
		}
	}
}

func TestCPUContentionNeedsEnoughPreemptionsToTrustTheMean(t *testing.T) {
	cur := []*dto.MetricFamily{blocked(2, 4)}

	if got := evalOnce(t, cpuContentionRule(), nil, cur, time.Minute); len(got) != 0 {
		t.Errorf("fired on a 2s mean drawn from two preemptions: %v.\n\nAn idle pod that "+
			"gets descheduled twice, once slowly, produces a mean above any threshold. "+
			"A contended workload produced 47540 samples in the same window.", got)
	}
}

func TestCPUContentionFiresOnceThereAreEnoughPreemptions(t *testing.T) {
	cur := []*dto.MetricFamily{blocked(1000, 110)}

	got := evalOnce(t, cpuContentionRule(), nil, cur, time.Minute)
	if len(got) != 1 {
		t.Fatalf("expected one issue at a 110ms mean over 1000 preemptions, got %d", len(got))
	}
	var sawFloor bool
	for _, e := range got[0].Evidence {
		if e.Name == "preemptions" {
			sawFloor = true
		}
	}
	if !sawFloor {
		t.Error("the preemption count is not reported as evidence")
	}
}
