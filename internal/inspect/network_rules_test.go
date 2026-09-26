package inspect

import (
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/gma1k/podtrace/internal/diagnose/detector"
)

func connections(total, failed float64) []*dto.MetricFamily {
	return []*dto.MetricFamily{
		counterFamily(familyConnections,
			counter(total-failed, workloadLabels(label("transport", "tcp"), label("outcome", "ok"))...),
			counter(failed, workloadLabels(label("transport", "tcp"), label("outcome", "error"))...),
		),
	}
}

func TestConnectionFailuresFireAboveTheErrorRateThreshold(t *testing.T) {
	got := evalOnce(t, connectionFailureRateRule(), nil, connections(100, 20), time.Minute)
	if len(got) != 1 {
		t.Fatalf("expected one issue at a 20%% failure rate, got %d", len(got))
	}
	if got[0].ID != detector.IDConnectionFailureRate {
		t.Errorf("wrong id: %q", got[0].ID)
	}
	if !strings.Contains(got[0].Message, "20.0%") {
		t.Errorf("message does not carry the rate: %q", got[0].Message)
	}
}

func TestConnectionFailuresStayQuietBelowTheErrorRateThreshold(t *testing.T) {
	if got := evalOnce(t, connectionFailureRateRule(), nil, connections(100, 2), time.Minute); len(got) != 0 {
		t.Errorf("fired at a 2%% failure rate against a 5%% threshold: %v", got)
	}
}

func TestConnectionFailuresStayQuietBelowTheTrafficFloor(t *testing.T) {
	if got := evalOnce(t, connectionFailureRateRule(), nil, connections(4, 4), time.Minute); len(got) != 0 {
		t.Errorf("a 100%% failure rate over four connections paged someone: %v", got)
	}
}

func TestConnectionFailuresNeedTwoSnapshots(t *testing.T) {
	start := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	cur, err := Take(&fixedGatherer{families: connections(100, 50)}, start)
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if got := connectionFailureRateRule().Eval(Window{Cur: cur}, DefaultThresholds()); len(got) != 0 {
		t.Errorf("fired on the first evaluation, with no window to rate over: %v", got)
	}
}

func latency(total uint64, withinBound uint64) []*dto.MetricFamily {
	return []*dto.MetricFamily{
		histogramFamily(familyNetworkLatency, bucketHistogram(total, 100, []*dto.Bucket{
			bucket(0.01, withinBound/2),
			bucket(0.1, withinBound),
			bucket(30, total),
		}, workloadLabels(label("direction", "egress"), label("transport", "tcp"))...)),
	}
}

func TestSpikeRateFiresWhenTooManyOperationsExceedTheBound(t *testing.T) {
	got := evalOnce(t, rttSpikeRule(), nil, latency(1000, 900), time.Minute)
	if len(got) != 1 {
		t.Fatalf("expected one issue at a 10%% spike rate, got %d", len(got))
	}
	if got[0].ID != detector.IDRTTSpikeRate {
		t.Errorf("wrong id: %q", got[0].ID)
	}
}

func TestSpikeRateStaysQuietBelowTheSpikeRateThreshold(t *testing.T) {
	if got := evalOnce(t, rttSpikeRule(), nil, latency(1000, 990), time.Minute); len(got) != 0 {
		t.Errorf("fired at a 1%% spike rate against a 5%% threshold: %v", got)
	}
}

func TestSpikeRateStaysSilentWhenTheBoundIsNotABucketBoundary(t *testing.T) {
	cur := []*dto.MetricFamily{
		histogramFamily(familyNetworkLatency, bucketHistogram(1000, 900, []*dto.Bucket{
			bucket(0.01, 100), bucket(30, 1000),
		}, workloadLabels(label("direction", "egress"), label("transport", "tcp"))...)),
	}
	if got := evalOnce(t, rttSpikeRule(), nil, cur, time.Minute); len(got) != 0 {
		t.Errorf("reported a spike rate the histogram cannot support: %v", got)
	}
}

func TestSpikeRateRemediationDoesNotBlameTheNetworkOutright(t *testing.T) {
	got := evalOnce(t, rttSpikeRule(), nil, latency(1000, 500), time.Minute)
	if len(got) != 1 {
		t.Fatalf("expected one issue, got %d", len(got))
	}
	if !strings.Contains(got[0].Remediation, "peer") {
		t.Errorf("remediation sends the operator to the wire without mentioning a slow peer: %q",
			got[0].Remediation)
	}
}

func TestSpikeRateAggregatesAcrossDirections(t *testing.T) {
	cur := []*dto.MetricFamily{
		histogramFamily(familyNetworkLatency,
			bucketHistogram(500, 50, []*dto.Bucket{bucket(0.1, 500), bucket(30, 500)},
				workloadLabels(label("direction", "egress"), label("transport", "tcp"))...),
			bucketHistogram(500, 50, []*dto.Bucket{bucket(0.1, 300), bucket(30, 500)},
				workloadLabels(label("direction", "ingress"), label("transport", "tcp"))...),
		),
	}
	got := evalOnce(t, rttSpikeRule(), nil, cur, time.Minute)
	if len(got) != 1 {
		t.Fatalf("expected one issue for the workload, not one per direction, got %d", len(got))
	}
	if !strings.Contains(got[0].Message, "1000 samples") {
		t.Errorf("both directions were not summed into one denominator: %q", got[0].Message)
	}
}

func kernelRTT(total uint64, withinBound uint64) *dto.MetricFamily {
	return histogramFamily(familyNetworkRTT, bucketHistogram(total, 10, []*dto.Bucket{
		bucket(0.01, withinBound/2),
		bucket(0.1, withinBound),
		bucket(30, total),
	}, workloadLabels()...))
}

func TestSpikeRatePrefersTheKernelRTTWhenItIsPresent(t *testing.T) {
	cur := append(latency(1000, 1000), kernelRTT(1000, 800))

	got := evalOnce(t, rttSpikeRule(), nil, cur, time.Minute)
	if len(got) != 1 {
		t.Fatalf("expected one issue, got %d", len(got))
	}
	if !strings.Contains(got[0].Message, "kernel smoothed RTT") {
		t.Errorf("the rule did not use the kernel RTT family: %q", got[0].Message)
	}
	if strings.Contains(got[0].Remediation, "slow peer") {
		t.Errorf("the kernel-RTT remediation still hedges about the peer: %q", got[0].Remediation)
	}
}

func TestSpikeRateFallsBackToSyscallLatencyWithoutTheSockOpsHook(t *testing.T) {
	got := evalOnce(t, rttSpikeRule(), nil, latency(1000, 800), time.Minute)
	if len(got) != 1 {
		t.Fatalf("expected one issue, got %d", len(got))
	}
	if !strings.Contains(got[0].Message, "socket operation latency") {
		t.Errorf("the fallback did not name its source: %q", got[0].Message)
	}
	if !strings.Contains(got[0].Remediation, "sock_ops") {
		t.Errorf("the fallback remediation does not mention the better measurement: %q",
			got[0].Remediation)
	}
}

func TestSpikeRateIgnoresSyscallLatencyOnceTheKernelRTTExists(t *testing.T) {
	cur := append(latency(1000, 100), kernelRTT(1000, 1000))

	if got := evalOnce(t, rttSpikeRule(), nil, cur, time.Minute); len(got) != 0 {
		t.Errorf("a healthy kernel RTT was overruled by slow syscalls: %v", got)
	}
}

func TestConnectionFailuresIgnoreASeriesThatReset(t *testing.T) {
	prev := connections(10000, 5000)
	cur := connections(100, 50)

	if got := evalOnce(t, connectionFailureRateRule(), prev, cur, time.Minute); len(got) != 0 {
		t.Errorf("a counter reset was read as a failure spike: %v", got)
	}
}

func TestConnectionFailuresSkipAWorkloadWithNoAttempts(t *testing.T) {
	cur := []*dto.MetricFamily{
		counterFamily(familyConnections,
			counter(0, workloadLabels(label("transport", "tcp"), label("outcome", "ok"))...)),
	}
	if got := evalOnce(t, connectionFailureRateRule(), nil, cur, time.Minute); len(got) != 0 {
		t.Errorf("a workload with zero attempts produced an issue: %v", got)
	}
}

func TestSpikeRateIgnoresASeriesThatReset(t *testing.T) {
	prev := latency(10000, 10000)
	cur := latency(100, 10)

	if got := evalOnce(t, rttSpikeRule(), prev, cur, time.Minute); len(got) != 0 {
		t.Errorf("a counter reset was read as a spike: %v", got)
	}
}

func TestSpikeRateSkipsAHistogramWithNoObservations(t *testing.T) {
	cur := []*dto.MetricFamily{
		histogramFamily(familyNetworkLatency, bucketHistogram(0, 0, []*dto.Bucket{
			bucket(0.1, 0),
		}, workloadLabels(label("direction", "egress"), label("transport", "tcp"))...)),
	}
	if got := evalOnce(t, rttSpikeRule(), nil, cur, time.Minute); len(got) != 0 {
		t.Errorf("an empty histogram produced an issue: %v", got)
	}
}
