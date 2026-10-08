package inspect

import (
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/gma1k/podtrace/internal/diagnose/detector"
)

func tlsFamilies(handshakes uint64, errorsByKind map[string]float64) []*dto.MetricFamily {
	var errs []*dto.Metric
	for kind, n := range errorsByKind {
		errs = append(errs, counter(n, workloadLabels(label("kind", kind))...))
	}
	return []*dto.MetricFamily{
		histogramFamily(familyTLSHandshake, bucketHistogram(handshakes, 1, []*dto.Bucket{bucket(0.1, handshakes)}, workloadLabels()...)),
		counterFamily(familyErrors, errs...),
	}
}

func evalTLS(t *testing.T, prev, cur []*dto.MetricFamily, thresholds Thresholds) []detector.Issue {
	t.Helper()
	start := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	before, err := Take(&fixedGatherer{families: prev}, start)
	if err != nil {
		t.Fatal(err)
	}
	after, err := Take(&fixedGatherer{families: cur}, start.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return tlsHandshakeFailureRule().Eval(Window{Prev: before, Cur: after}, thresholds)
}

func TestTLSHandshakeFailuresFireAboveTheShare(t *testing.T) {
	got := evalTLS(t, nil, tlsFamilies(200, map[string]float64{"tls": 20}), DefaultThresholds())
	if len(got) != 1 || got[0].ID != detector.IDTLSHandshakeFailureRate {
		t.Fatalf("issues = %v, want one tls.handshake_failure_rate at 10%%", got)
	}
	if !strings.Contains(got[0].Message, "10.0% of 200 handshakes") {
		t.Errorf("message = %q", got[0].Message)
	}
	if !strings.Contains(got[0].Remediation, "certificates") {
		t.Errorf("remediation = %q", got[0].Remediation)
	}
}

func TestTLSHandshakeFailuresCountOnlyTLSErrors(t *testing.T) {
	cur := tlsFamilies(200, map[string]float64{"tls": 2, "network": 150, "l7": 40})
	if got := evalTLS(t, nil, cur, DefaultThresholds()); len(got) != 0 {
		t.Errorf("network and l7 errors were counted as handshake failures: %v", got)
	}
}

func TestTLSHandshakeFailuresStayQuietAtOrBelowTheShare(t *testing.T) {
	if got := evalTLS(t, nil, tlsFamilies(100, map[string]float64{"tls": 5}), DefaultThresholds()); len(got) != 0 {
		t.Errorf("exactly 5%% failed and the rule fired: %v", got)
	}
}

func TestTLSHandshakeFailuresStayQuietBelowTheTrafficFloor(t *testing.T) {
	if got := evalTLS(t, nil, tlsFamilies(3, map[string]float64{"tls": 3}), DefaultThresholds()); len(got) != 0 {
		t.Errorf("three failed handshakes in a minute, under the 0.1/s floor, fired: %v", got)
	}
}

func TestTLSHandshakeFailuresAreOffWithoutAThreshold(t *testing.T) {
	off := DefaultThresholds()
	off.TLSHandshakeFailurePercent = 0
	if got := evalTLS(t, nil, tlsFamilies(600, map[string]float64{"tls": 600}), off); len(got) != 0 {
		t.Errorf("fired with no threshold: %v", got)
	}
}

func TestTLSHandshakeFailuresSkipCountersThatReset(t *testing.T) {
	prev := tlsFamilies(900, map[string]float64{"tls": 900})
	cur := tlsFamilies(100, map[string]float64{"tls": 100})
	if got := evalTLS(t, prev, cur, DefaultThresholds()); len(got) != 0 {
		t.Errorf("a restarted agent's counters fired: %v", got)
	}
}

func TestTLSErrorsWithoutHandshakesRaiseNothing(t *testing.T) {
	cur := []*dto.MetricFamily{counterFamily(familyErrors, counter(50, workloadLabels(label("kind", "tls"))...))}
	if got := evalTLS(t, nil, cur, DefaultThresholds()); len(got) != 0 {
		t.Errorf("failures with no handshake to divide by fired: %v", got)
	}
}

func TestTLSHandshakeFailuresNeverExceedEveryHandshake(t *testing.T) {
	got := evalTLS(t, nil, tlsFamilies(10, map[string]float64{"tls": 30}), DefaultThresholds())
	if len(got) != 1 || !strings.Contains(got[0].Message, "100.0% of 10 handshakes") {
		t.Errorf("issues = %v, want the share capped at 100%%", got)
	}
}
