package inspect

import (
	"math"
	"testing"
)

func cumulative(bounds []float64, counts []uint64) []Bucket {
	out := make([]Bucket, len(bounds))
	var total uint64
	for i := range bounds {
		total += counts[i]
		out[i] = Bucket{UpperBound: bounds[i], Count: total}
	}
	return out
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestQuantileInterpolatesInsideTheBucket(t *testing.T) {
	d := Delta{Count: 100, Buckets: cumulative([]float64{0.1, 0.2, 0.4}, []uint64{50, 40, 10})}

	for _, tt := range []struct{ q, want float64 }{
		{0.5, 0.1},
		{0.7, 0.15},
		{0.95, 0.3},
	} {
		got, ok := d.Quantile(tt.q)
		if !ok || !near(got, tt.want) {
			t.Errorf("Quantile(%v) = %v, %v; want %v", tt.q, got, ok, tt.want)
		}
	}
}

func TestQuantileInTheOverflowBucketIsTheLastFiniteBound(t *testing.T) {
	d := Delta{Count: 10, Buckets: cumulative([]float64{1, math.Inf(1)}, []uint64{5, 5})}
	got, ok := d.Quantile(0.99)
	if !ok || got != 1 {
		t.Errorf("Quantile(0.99) = %v, %v; an observation past the last bound is only known to "+
			"exceed it, so the estimate is that bound", got, ok)
	}
}

func TestQuantileSkipsEmptyBucketsAndStopsAtTheLastBound(t *testing.T) {
	d := Delta{Count: 4, Buckets: []Bucket{{UpperBound: 1, Count: 0}, {UpperBound: 2, Count: 0}, {UpperBound: 3, Count: 4}}}
	if got, ok := d.Quantile(0.0001); !ok || got <= 2 || got > 3 {
		t.Errorf("Quantile = %v, %v; want within the only bucket that holds observations", got, ok)
	}
	stuck := Delta{Count: 2, Buckets: []Bucket{{UpperBound: 1, Count: 0}, {UpperBound: 2, Count: 1}}}
	if got, ok := stuck.Quantile(0.9); !ok || got != 2 {
		t.Errorf("Quantile past every bucket's count = %v, %v; want the last bound", got, ok)
	}
}

func TestQuantileRefusesWhatItCannotAnswer(t *testing.T) {
	buckets := cumulative([]float64{1}, []uint64{1})
	for name, d := range map[string]Delta{
		"nothing observed": {Buckets: buckets},
		"counter reset":    {Count: 1, Reset: true, Buckets: buckets},
		"no buckets":       {Count: 1},
	} {
		if _, ok := d.Quantile(0.5); ok {
			t.Errorf("%s: Quantile answered", name)
		}
	}
	d := Delta{Count: 1, Buckets: buckets}
	for _, q := range []float64{0, 1, -0.1, 1.5} {
		if _, ok := d.Quantile(q); ok {
			t.Errorf("Quantile(%v) answered; only 0 < q < 1 is a quantile", q)
		}
	}
}

func TestMergeDeltasAddsSeriesAsOne(t *testing.T) {
	a := Delta{Value: 3, Count: 10, Sum: 1, Buckets: cumulative([]float64{0.1, 0.2}, []uint64{8, 2})}
	b := Delta{Value: 4, Count: 20, Sum: 2, Buckets: cumulative([]float64{0.1, 0.4}, []uint64{10, 10})}
	reset := Delta{Count: 99, Reset: true, Buckets: cumulative([]float64{0.1}, []uint64{99})}

	got := MergeDeltas([]Delta{a, b, reset})
	if got.Count != 30 || got.Sum != 3 || got.Value != 7 {
		t.Errorf("count=%d sum=%v value=%v, want 30, 3, 7 with the reset series left out", got.Count, got.Sum, got.Value)
	}
	want := []Bucket{{0.1, 18}, {0.2, 20}, {0.4, 30}}
	if len(got.Buckets) != len(want) {
		t.Fatalf("buckets = %v, want %v", got.Buckets, want)
	}
	for i := range want {
		if got.Buckets[i] != want[i] {
			t.Errorf("bucket %d = %v, want %v", i, got.Buckets[i], want[i])
		}
	}
	if q, ok := got.Quantile(0.5); !ok || q > 0.1 {
		t.Errorf("median of the merged series = %v, %v; 18 of 30 observations are at or below 0.1", q, ok)
	}
}

func TestMergingNothingIsEmpty(t *testing.T) {
	if got := MergeDeltas(nil); got.Count != 0 || len(got.Buckets) != 0 {
		t.Errorf("MergeDeltas(nil) = %+v", got)
	}
}
