package inspect

import (
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/gma1k/podtrace/internal/diagnose/detector"
)

func dnsLookups(total, withinBound uint64) []*dto.MetricFamily {
	return []*dto.MetricFamily{
		histogramFamily(familyDNSLatency, bucketHistogram(total, 1, []*dto.Bucket{
			bucket(0.001, withinBound/2),
			bucket(0.1, withinBound),
			bucket(30, total),
		}, workloadLabels()...)),
	}
}

func TestSlowDNSFiresWhenTooManyLookupsExceedTheBound(t *testing.T) {
	got := evalOnce(t, dnsSlowLookupRule(), nil, dnsLookups(1000, 900), time.Minute)
	if len(got) != 1 {
		t.Fatalf("expected one issue at a 10%% slow-lookup rate, got %d", len(got))
	}
	if got[0].ID != detector.IDDNSSlowLookupRate {
		t.Errorf("wrong id: %q", got[0].ID)
	}
	if !strings.Contains(got[0].Message, "10.0% of 1000 lookups slower than 100ms") {
		t.Errorf("message does not state the measurement: %q", got[0].Message)
	}
	if !strings.Contains(got[0].Remediation, "upstream") {
		t.Errorf("remediation does not separate the upstream resolver from the path to CoreDNS: %q", got[0].Remediation)
	}
}

func TestSlowDNSStaysQuietAtTheIdleFloor(t *testing.T) {
	if got := evalOnce(t, dnsSlowLookupRule(), nil, dnsLookups(10000, 9974), time.Minute); len(got) != 0 {
		t.Errorf("fired at the 0.26%% idle floor: %v", got)
	}
}

func TestSlowDNSStaysQuietBelowTheTrafficFloor(t *testing.T) {
	if got := evalOnce(t, dnsSlowLookupRule(), nil, dnsLookups(5, 0), time.Minute); len(got) != 0 {
		t.Errorf("five slow lookups in a minute, under the 0.1/s floor, fired: %v", got)
	}
}

func TestSlowDNSStaysSilentWhenTheBoundIsNotABucketBoundary(t *testing.T) {
	cur := []*dto.MetricFamily{
		histogramFamily(familyDNSLatency, bucketHistogram(1000, 50, []*dto.Bucket{
			bucket(0.001, 100), bucket(30, 1000),
		}, workloadLabels()...)),
	}
	if got := evalOnce(t, dnsSlowLookupRule(), nil, cur, time.Minute); len(got) != 0 {
		t.Errorf("reported a slow-lookup rate the histogram cannot support: %v", got)
	}
}

func TestSlowDNSReadsAKernelAggregatedNativeHistogram(t *testing.T) {
	slow := nativeHistogram(1000, 30, 0, []nativeSpan{{-40, 1}, {19, 1}}, []int64{850, -700})
	cur := []*dto.MetricFamily{histogramFamily(familyDNSLatency, slow)}

	got := evalOnce(t, dnsSlowLookupRule(), nil, cur, time.Minute)
	if len(got) != 1 {
		t.Fatalf("expected one issue for 150 of 1000 lookups at 177ms, got %d", len(got))
	}
	if !strings.Contains(got[0].Message, "15.0%") {
		t.Errorf("native buckets were not read: %q", got[0].Message)
	}
}

func TestSlowDNSIgnoresASeriesThatReset(t *testing.T) {
	prev := dnsLookups(5000, 5000)
	cur := dnsLookups(1000, 100)
	if got := evalOnce(t, dnsSlowLookupRule(), prev, cur, time.Minute); len(got) != 0 {
		t.Errorf("a counter reset was read as lookups: %v", got)
	}
}

func TestSlowDNSIsOffWithoutABound(t *testing.T) {
	start := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	before, _ := Take(&fixedGatherer{}, start)
	after, _ := Take(&fixedGatherer{families: dnsLookups(1000, 0)}, start.Add(time.Minute))
	thresholds := DefaultThresholds()
	thresholds.DNSSlowBound = 0
	if got := dnsSlowLookupRule().Eval(Window{Prev: before, Cur: after}, thresholds); len(got) != 0 {
		t.Errorf("fired with no bound configured: %v", got)
	}
	if got := dnsSlowLookupRule().Eval(Window{Cur: after}, DefaultThresholds()); len(got) != 0 {
		t.Errorf("fired from a single snapshot: %v", got)
	}
}
