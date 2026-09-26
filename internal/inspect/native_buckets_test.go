package inspect

import (
	"math"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"google.golang.org/protobuf/proto"
)

type nativeSpan struct {
	offset int32
	length uint32
}

func nativeHistogram(count uint64, sum float64, zero uint64, spans []nativeSpan, deltas []int64) *dto.Metric {
	h := &dto.Histogram{
		SampleCount:   proto.Uint64(count),
		SampleSum:     proto.Float64(sum),
		Schema:        proto.Int32(3),
		ZeroThreshold: proto.Float64(1e-12),
		ZeroCount:     proto.Uint64(zero),
		PositiveDelta: deltas,
	}
	for _, s := range spans {
		h.PositiveSpan = append(h.PositiveSpan, &dto.BucketSpan{Offset: proto.Int32(s.offset), Length: proto.Uint32(s.length)})
	}
	return &dto.Metric{Label: workloadLabels(), Histogram: h}
}

func edge(index int) float64 { return math.Pow(2, float64(index)/8) }

func TestANativeHistogramDecodesIntoCumulativeBuckets(t *testing.T) {
	got := nativeBuckets(nativeHistogram(10, 1, 1, []nativeSpan{{-30, 2}, {3, 1}}, []int64{4, -1, 2}).GetHistogram())

	want := []Bucket{
		{UpperBound: 1e-12, Count: 1},
		{UpperBound: edge(-30), Count: 5},
		{UpperBound: edge(-29), Count: 8},
		{UpperBound: edge(-25), Count: 13},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d buckets %v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i].Count != want[i].Count || math.Abs(got[i].UpperBound-want[i].UpperBound) > want[i].UpperBound*1e-12 {
			t.Errorf("bucket %d = %+v, want %+v; spans give indexes relative to the previous "+
				"span's end and deltas give counts relative to the previous bucket", i, got[i], want[i])
		}
	}
}

func TestAMalformedNativeHistogramDecodesToNothing(t *testing.T) {
	for name, m := range map[string]*dto.Metric{
		"fewer deltas than spans claim": nativeHistogram(5, 1, 0, []nativeSpan{{0, 3}}, []int64{1, 1}),
		"a negative bucket count":       nativeHistogram(5, 1, 0, []nativeSpan{{0, 2}}, []int64{2, -5}),
		"nothing observed":              nativeHistogram(0, 0, 0, nil, nil),
	} {
		if got := nativeBuckets(m.GetHistogram()); got != nil {
			t.Errorf("%s decoded to %v; a rule reading these would see counts no observation made", name, got)
		}
	}
}

func TestTheSnapshotReadsANativeHistogram(t *testing.T) {
	d := deltaOf(t, familyNetworkRTT, nil, []*dto.MetricFamily{
		histogramFamily(familyNetworkRTT, nativeHistogram(50, 7.5, 0, []nativeSpan{{-21, 1}}, []int64{50})),
	})
	if !d.Sample.NativeBuckets || len(d.Buckets) != 1 {
		t.Fatalf("a native histogram produced no buckets (native=%v, %v)", d.Sample.NativeBuckets, d.Buckets)
	}
	share, ok := d.FractionAbove(0.1)
	if !ok || share != 100 {
		t.Errorf("FractionAbove(100ms) = %v, %v, want 100%%: every observation sits in "+
			"(%g, %g], wholly above the bound, though 100ms is no bucket edge", share, ok, edge(-22), edge(-21))
	}
}

func TestANativeBoundInsideABucketCountsOnlyWhatIsCertainlyAbove(t *testing.T) {
	d := deltaOf(t, familyNetworkRTT, nil, []*dto.MetricFamily{
		histogramFamily(familyNetworkRTT, nativeHistogram(100, 9, 0, []nativeSpan{{-26, 2}}, []int64{60, -20})),
	})
	share, ok := d.FractionAbove(0.1)
	if !ok || share != 40 {
		t.Errorf("FractionAbove(100ms) = %v, %v, want 40%%: the 60 observations in the bucket "+
			"holding 100ms may lie on either side of it, so only the 40 above that bucket count", share, ok)
	}
	if _, ok := d.FractionAbove(0); ok {
		t.Error("a zero bound was answered")
	}
}

func TestABucketFirstSeenThisWindowIsNotCreditedWithOlderObservations(t *testing.T) {
	prev := []*dto.MetricFamily{
		histogramFamily(familyNetworkRTT, nativeHistogram(40, 0.4, 0, []nativeSpan{{-30, 1}}, []int64{40})),
	}
	cur := []*dto.MetricFamily{
		histogramFamily(familyNetworkRTT, nativeHistogram(50, 1.9, 0, []nativeSpan{{-30, 1}, {7, 1}}, []int64{40, -30})),
	}
	d := deltaOf(t, familyNetworkRTT, prev, cur)
	share, ok := d.FractionAbove(0.1)
	if !ok || d.Count != 10 || share != 100 {
		t.Errorf("count=%d share=%v ok=%v, want 10 new observations, all slow.\n\nThe slow "+
			"bucket first appears in this window. Subtracting zero from its cumulative count "+
			"credited it with the 40 fast observations below it, reporting 50 slow ones.", d.Count, share, ok)
	}
}

func TestNativeBucketsCountingMoreThanTheSampleCountAreRefused(t *testing.T) {
	d := deltaOf(t, familyNetworkRTT, nil, []*dto.MetricFamily{
		histogramFamily(familyNetworkRTT, nativeHistogram(5, 1, 0, []nativeSpan{{-30, 1}}, []int64{50})),
	})
	if _, ok := d.FractionAbove(0.1); ok {
		t.Error("a histogram whose buckets hold 50 observations but whose count is 5 was " +
			"answered; the share it reported would come from no real window")
	}
}
