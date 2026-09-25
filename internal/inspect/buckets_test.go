package inspect

import (
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
)

func bucket(bound float64, cumulative uint64) *dto.Bucket {
	b, c := bound, cumulative
	return &dto.Bucket{UpperBound: &b, CumulativeCount: &c}
}

func bucketHistogram(count uint64, sum float64, buckets []*dto.Bucket, labels ...*dto.LabelPair) *dto.Metric {
	c, s := count, sum
	return &dto.Metric{
		Label: labels,
		Histogram: &dto.Histogram{
			SampleCount: &c,
			SampleSum:   &s,
			Bucket:      buckets,
		},
	}
}

func deltaOf(t *testing.T, family string, prev, cur []*dto.MetricFamily) Delta {
	t.Helper()
	start := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	before, err := Take(&fixedGatherer{families: prev}, start)
	if err != nil {
		t.Fatalf("Take(prev): %v", err)
	}
	after, err := Take(&fixedGatherer{families: cur}, start.Add(time.Minute))
	if err != nil {
		t.Fatalf("Take(cur): %v", err)
	}
	deltas := Window{Prev: before, Cur: after}.Deltas(family)
	if len(deltas) != 1 {
		t.Fatalf("expected one delta, got %d", len(deltas))
	}
	return deltas[0]
}

func TestFractionAboveReportsTheShareBeyondABucketBound(t *testing.T) {
	d := deltaOf(t, familyNetworkLatency, nil, []*dto.MetricFamily{
		histogramFamily(familyNetworkLatency, bucketHistogram(1000, 50, []*dto.Bucket{
			bucket(0.01, 500), bucket(0.1, 900), bucket(1, 1000),
		}, workloadLabels()...)),
	})

	got, ok := d.FractionAbove(0.1)
	if !ok {
		t.Fatal("FractionAbove refused a bound that is a bucket boundary")
	}
	if got != 10 {
		t.Errorf("expected 10%% above 0.1s, got %v", got)
	}
}

func TestFractionAboveRefusesABoundThatIsNotABucketBoundary(t *testing.T) {
	d := deltaOf(t, familyNetworkLatency, nil, []*dto.MetricFamily{
		histogramFamily(familyNetworkLatency, bucketHistogram(1000, 50, []*dto.Bucket{
			bucket(0.01, 500), bucket(1, 1000),
		}, workloadLabels()...)),
	})

	if _, ok := d.FractionAbove(0.1); ok {
		t.Error("FractionAbove interpolated between buckets instead of refusing")
	}
}

func TestFractionAboveRefusesAHistogramWithNoBuckets(t *testing.T) {
	d := deltaOf(t, familyNetworkLatency, nil, []*dto.MetricFamily{
		histogramFamily(familyNetworkLatency, histogram(1000, 50, workloadLabels()...)),
	})

	if _, ok := d.FractionAbove(0.1); ok {
		t.Error("FractionAbove answered from a histogram carrying no buckets")
	}
}

func TestFractionAboveRefusesAfterACounterReset(t *testing.T) {
	prev := []*dto.MetricFamily{
		histogramFamily(familyNetworkLatency, bucketHistogram(1000, 50, []*dto.Bucket{
			bucket(0.1, 900),
		}, workloadLabels()...)),
	}
	cur := []*dto.MetricFamily{
		histogramFamily(familyNetworkLatency, bucketHistogram(10, 1, []*dto.Bucket{
			bucket(0.1, 9),
		}, workloadLabels()...)),
	}

	d := deltaOf(t, familyNetworkLatency, prev, cur)
	if !d.Reset {
		t.Fatal("a histogram that went backwards was not marked as a reset")
	}
	if _, ok := d.FractionAbove(0.1); ok {
		t.Error("FractionAbove answered across a reset")
	}
}

func TestBucketsAreDifferencedAcrossTheWindow(t *testing.T) {
	prev := []*dto.MetricFamily{
		histogramFamily(familyNetworkLatency, bucketHistogram(1000, 50, []*dto.Bucket{
			bucket(0.1, 1000),
		}, workloadLabels()...)),
	}
	cur := []*dto.MetricFamily{
		histogramFamily(familyNetworkLatency, bucketHistogram(1100, 60, []*dto.Bucket{
			bucket(0.1, 1020),
		}, workloadLabels()...)),
	}

	d := deltaOf(t, familyNetworkLatency, prev, cur)
	got, ok := d.FractionAbove(0.1)
	if !ok {
		t.Fatal("FractionAbove refused a differenced window")
	}
	if got != 80 {
		t.Errorf("expected 80%% of the window's 100 observations above 0.1s, got %v", got)
	}
}

func TestFractionAboveRefusesABucketLargerThanItsOwnTotal(t *testing.T) {
	d := deltaOf(t, familyNetworkLatency, nil, []*dto.MetricFamily{
		histogramFamily(familyNetworkLatency, bucketHistogram(100, 5, []*dto.Bucket{
			bucket(0.1, 500),
		}, workloadLabels()...)),
	})

	if _, ok := d.FractionAbove(0.1); ok {
		t.Error("a bucket holding more observations than the histogram was answered rather " +
			"than refused; the subtraction would underflow into a huge spike rate")
	}
}

func TestBucketsThatGoBackwardsYieldNoBucketsAtAll(t *testing.T) {
	prev := []*dto.MetricFamily{
		histogramFamily(familyNetworkLatency, bucketHistogram(1000, 50, []*dto.Bucket{
			bucket(0.01, 900), bucket(0.1, 950),
		}, workloadLabels()...)),
	}
	cur := []*dto.MetricFamily{
		histogramFamily(familyNetworkLatency, bucketHistogram(1100, 60, []*dto.Bucket{
			bucket(0.01, 10), bucket(0.1, 1000),
		}, workloadLabels()...)),
	}

	d := deltaOf(t, familyNetworkLatency, prev, cur)
	if d.Reset {
		t.Fatal("the fixture was meant to keep a growing total so only one bucket regresses")
	}
	if len(d.Buckets) != 0 {
		t.Errorf("a partially rewound histogram kept its buckets: %+v", d.Buckets)
	}
	if _, ok := d.FractionAbove(0.1); ok {
		t.Error("FractionAbove answered from a partially rewound histogram")
	}
}
