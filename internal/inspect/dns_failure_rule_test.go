package inspect

import (
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/gma1k/podtrace/internal/diagnose/detector"
)

func dnsAnswerCounts(counts map[string]float64) []*dto.MetricFamily {
	var metrics []*dto.Metric
	for answer, n := range counts {
		metrics = append(metrics, counter(n, workloadLabels(label("rcode", answer))...))
	}
	return []*dto.MetricFamily{counterFamily(familyDNSLookups, metrics...)}
}

func evalDNSFailures(t *testing.T, counts map[string]float64, thresholds Thresholds) []detector.Issue {
	t.Helper()
	start := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	before, err := Take(&fixedGatherer{}, start)
	if err != nil {
		t.Fatal(err)
	}
	after, err := Take(&fixedGatherer{families: dnsAnswerCounts(counts)}, start.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return dnsFailureRateRule().Eval(Window{Prev: before, Cur: after}, thresholds)
}

func TestDNSFailuresFireAboveTheShareAndNameTheCommonestFailure(t *testing.T) {
	got := evalDNSFailures(t, map[string]float64{"NOERROR": 160, "NXDOMAIN": 20, "timeout": 15, "SERVFAIL": 5}, DefaultThresholds())
	if len(got) != 1 || got[0].ID != detector.IDDNSFailureRate {
		t.Fatalf("issues = %v, want one dns.failure_rate at 10%% failed", got)
	}
	if !strings.Contains(got[0].Message, "10.0% of 200 lookups, mostly timeout") {
		t.Errorf("message = %q", got[0].Message)
	}
	if !strings.Contains(got[0].Remediation, "conntrack") {
		t.Errorf("a timeout's remediation does not point at reachability: %q", got[0].Remediation)
	}
}

func TestDNSFailuresIgnoreNXDOMAIN(t *testing.T) {
	if got := evalDNSFailures(t, map[string]float64{"NOERROR": 10, "NXDOMAIN": 190}, DefaultThresholds()); len(got) != 0 {
		t.Errorf("NXDOMAIN answers fired: %v", got)
	}
}

func TestDNSFailuresStayQuietAtOrBelowTheShare(t *testing.T) {
	if got := evalDNSFailures(t, map[string]float64{"NOERROR": 95, "REFUSED": 5}, DefaultThresholds()); len(got) != 0 {
		t.Errorf("exactly 5%% failed and the rule fired above a 5%% threshold: %v", got)
	}
}

func TestDNSFailuresStayQuietBelowTheTrafficFloor(t *testing.T) {
	if got := evalDNSFailures(t, map[string]float64{"SERVFAIL": 3}, DefaultThresholds()); len(got) != 0 {
		t.Errorf("three failed lookups in a minute, under the 0.1/s floor, fired: %v", got)
	}
}

func TestDNSFailuresAreOffWithoutAThreshold(t *testing.T) {
	off := DefaultThresholds()
	off.DNSFailureRatePercent = 0
	if got := evalDNSFailures(t, map[string]float64{"SERVFAIL": 600}, off); len(got) != 0 {
		t.Errorf("fired with no threshold: %v", got)
	}
}

func TestEveryDNSFailureHasItsOwnRemedy(t *testing.T) {
	seen := map[string]string{}
	for _, answer := range []string{"timeout", "SERVFAIL", "REFUSED", "other"} {
		r := remediationForDNSFailure(answer)
		for prev, text := range seen {
			if text == r {
				t.Errorf("%s and %s share a remedy: %q", answer, prev, r)
			}
		}
		seen[answer] = r
	}
}

func TestTheCommonestFailureIsStableOnATie(t *testing.T) {
	if got := topDNSFailure(map[string]float64{"timeout": 4, "SERVFAIL": 4, "other": 1}); got != "SERVFAIL" {
		t.Errorf("tie went to %q, want the first by name", got)
	}
}

func evalDNSFailuresBetween(t *testing.T, prev, cur map[string]float64) []detector.Issue {
	t.Helper()
	return evalOnce(t, dnsFailureRateRule(), dnsAnswerCounts(prev), dnsAnswerCounts(cur), time.Minute)
}

func TestDNSFailuresSkipACounterThatReset(t *testing.T) {
	if got := evalDNSFailuresBetween(t, map[string]float64{"SERVFAIL": 900}, map[string]float64{"SERVFAIL": 20}); len(got) != 0 {
		t.Errorf("a restarted agent's counters fired: %v", got)
	}
}

func TestDNSFailuresStayQuietForAWorkloadThatStoppedLookingUp(t *testing.T) {
	same := map[string]float64{"SERVFAIL": 600}
	if got := evalDNSFailuresBetween(t, same, same); len(got) != 0 {
		t.Errorf("no lookup in the interval and the rule fired: %v", got)
	}
}
