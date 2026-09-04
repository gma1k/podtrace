package workloadmetrics

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/gma1k/podtrace/internal/events"
)

func collectorLabelNames(t *testing.T, collector prometheus.Collector) []string {
	t.Helper()
	ch := make(chan *prometheus.Desc, 8)
	go func() {
		collector.Describe(ch)
		close(ch)
	}()
	var out []string
	for desc := range ch {
		if got := varLabelsRe.FindStringSubmatch(desc.String()); got != nil && got[1] != "" {
			for _, label := range strings.Split(got[1], ",") {
				out = append(out, strings.TrimSpace(label))
			}
		}
	}
	return out
}

func surfaceExercisingBatch() []*events.Event {
	return []*events.Event{
		{Type: events.EventHTTPResp, LatencyNS: 3_000_000, Details: "200", HTTPMethod: "GET", K8s: enriched()},
		{Type: events.EventGRPCMethod, LatencyNS: 4_000_000, Target: "/svc/Method", K8s: enriched()},
		{Type: events.EventRedisCmd, LatencyNS: 1_000_000, Details: "GET", K8s: enriched()},
		{Type: events.EventDNS, LatencyNS: 2_000_000, Target: "example.com", K8s: enriched()},
		{Type: events.EventTCPSend, LatencyNS: 500_000, Bytes: 4096, K8s: enriched()},
		{Type: events.EventWrite, LatencyNS: 700_000, Bytes: 128, K8s: enriched()},
		{Type: events.EventSchedSwitch, LatencyNS: 900_000, K8s: enriched()},
		{Type: events.EventOOMKill, K8s: enriched()},
	}
}

type staticGatherer struct {
	families []*dto.MetricFamily
	err      error
}

func (g staticGatherer) Gather() ([]*dto.MetricFamily, error) {
	return g.families, g.err
}

type failingGatherer struct{}

func (failingGatherer) Gather() ([]*dto.MetricFamily, error) {
	return nil, errors.New("registry exploded")
}

func produce(t *testing.T, g gatherer) []metricdata.Metrics {
	t.Helper()
	scopes, err := NewProducer(g).Produce(context.Background())
	if err != nil {
		t.Fatalf("Produce: %v", err)
	}
	if len(scopes) == 0 {
		return nil
	}
	if len(scopes) != 1 {
		t.Fatalf("got %d scopes, want 1", len(scopes))
	}
	if scopes[0].Scope.Name != producerScopeName {
		t.Errorf("scope name = %q, want %q", scopes[0].Scope.Name, producerScopeName)
	}
	return scopes[0].Metrics
}

func findMetric(t *testing.T, metrics []metricdata.Metrics, name string) metricdata.Metrics {
	t.Helper()
	for _, m := range metrics {
		if m.Name == name {
			return m
		}
	}
	names := make([]string, 0, len(metrics))
	for _, m := range metrics {
		names = append(names, m.Name)
	}
	t.Fatalf("metric %q not produced; got %v", name, names)
	return metricdata.Metrics{}
}

func counterFamily(name string, value float64, labels ...string) *dto.MetricFamily {
	return &dto.MetricFamily{
		Name:   proto.String(name),
		Help:   proto.String("help for " + name),
		Type:   dto.MetricType_COUNTER.Enum(),
		Metric: []*dto.Metric{{Label: labelPairs(labels...), Counter: &dto.Counter{Value: proto.Float64(value)}}},
	}
}

func labelPairs(kv ...string) []*dto.LabelPair {
	out := make([]*dto.LabelPair, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, &dto.LabelPair{Name: proto.String(kv[i]), Value: proto.String(kv[i+1])})
	}
	return out
}

func classicHistogramFamily(name string, count uint64, sum float64, cumulative map[float64]uint64) *dto.MetricFamily {
	buckets := make([]*dto.Bucket, 0, len(cumulative))
	for bound, c := range cumulative {
		buckets = append(buckets, &dto.Bucket{
			UpperBound:      proto.Float64(bound),
			CumulativeCount: proto.Uint64(c),
		})
	}
	return &dto.MetricFamily{
		Name: proto.String(name),
		Type: dto.MetricType_HISTOGRAM.Enum(),
		Metric: []*dto.Metric{{
			Histogram: &dto.Histogram{
				SampleCount: proto.Uint64(count),
				SampleSum:   proto.Float64(sum),
				Bucket:      buckets,
			},
		}},
	}
}

func TestCounterBecomesACumulativeMonotonicSum(t *testing.T) {
	metrics := produce(t, staticGatherer{families: []*dto.MetricFamily{
		counterFamily("podtrace_workload_l7_requests_total", 7, "namespace", "shop", "workload", "checkout"),
	}})

	m := findMetric(t, metrics, "podtrace_workload_l7_requests_total")
	sum, ok := m.Data.(metricdata.Sum[float64])
	if !ok {
		t.Fatalf("counter became %T, want metricdata.Sum[float64]", m.Data)
	}
	if sum.Temporality != metricdata.CumulativeTemporality {
		t.Errorf("temporality = %v, want cumulative; a Prometheus counter is cumulative and "+
			"labelling it delta makes a backend double-count every scrape", sum.Temporality)
	}
	if !sum.IsMonotonic {
		t.Error("IsMonotonic = false; a _total counter only ever rises and a backend needs to know")
	}
	if len(sum.DataPoints) != 1 {
		t.Fatalf("got %d data points, want 1", len(sum.DataPoints))
	}
	point := sum.DataPoints[0]
	if point.Value != 7 {
		t.Errorf("value = %v, want 7", point.Value)
	}
	if got, ok := point.Attributes.Value("namespace"); !ok || got.AsString() != "shop" {
		t.Errorf("namespace attribute = %v (present=%v), want shop", got.AsString(), ok)
	}
	if got, ok := point.Attributes.Value("workload"); !ok || got.AsString() != "checkout" {
		t.Errorf("workload attribute = %v (present=%v), want checkout", got.AsString(), ok)
	}
	if point.Time.IsZero() {
		t.Error("Time is zero; a data point with no timestamp is undeliverable")
	}
	if point.StartTime.IsZero() {
		t.Error("StartTime is zero; cumulative points need a start or rate() has no window")
	}
}

func TestGaugeBecomesAGauge(t *testing.T) {
	metrics := produce(t, staticGatherer{families: []*dto.MetricFamily{{
		Name:   proto.String("podtrace_workload_metrics_series_active"),
		Type:   dto.MetricType_GAUGE.Enum(),
		Metric: []*dto.Metric{{Gauge: &dto.Gauge{Value: proto.Float64(1234)}}},
	}}})

	m := findMetric(t, metrics, "podtrace_workload_metrics_series_active")
	gauge, ok := m.Data.(metricdata.Gauge[float64])
	if !ok {
		t.Fatalf("gauge became %T, want metricdata.Gauge[float64]", m.Data)
	}
	if len(gauge.DataPoints) != 1 || gauge.DataPoints[0].Value != 1234 {
		t.Fatalf("gauge data points = %+v, want a single 1234", gauge.DataPoints)
	}
}

func TestClassicHistogramBucketsAreDifferencedNotCumulative(t *testing.T) {
	metrics := produce(t, staticGatherer{families: []*dto.MetricFamily{
		classicHistogramFamily("podtrace_workload_dns_latency_seconds", 10, 1.5, map[float64]uint64{
			0.001:       2,
			0.01:        5,
			0.1:         9,
			math.Inf(1): 10,
		}),
	}})

	m := findMetric(t, metrics, "podtrace_workload_dns_latency_seconds")
	hist, ok := m.Data.(metricdata.Histogram[float64])
	if !ok {
		t.Fatalf("histogram became %T, want metricdata.Histogram[float64]", m.Data)
	}
	if hist.Temporality != metricdata.CumulativeTemporality {
		t.Errorf("temporality = %v, want cumulative", hist.Temporality)
	}
	point := hist.DataPoints[0]

	wantBounds := []float64{0.001, 0.01, 0.1}
	if len(point.Bounds) != len(wantBounds) {
		t.Fatalf("bounds = %v, want %v; +Inf is implicit in OTLP and must not appear as a bound",
			point.Bounds, wantBounds)
	}
	for i, want := range wantBounds {
		if point.Bounds[i] != want {
			t.Errorf("bounds[%d] = %v, want %v", i, point.Bounds[i], want)
		}
	}

	wantCounts := []uint64{2, 3, 4, 1}
	if len(point.BucketCounts) != len(point.Bounds)+1 {
		t.Fatalf("len(BucketCounts) = %d, len(Bounds) = %d; OTLP requires exactly one more count "+
			"than bounds (the overflow bucket)", len(point.BucketCounts), len(point.Bounds))
	}
	for i, want := range wantCounts {
		if point.BucketCounts[i] != want {
			t.Errorf("BucketCounts = %v, want %v; Prometheus counts are cumulative and must be "+
				"differenced, or every bucket over-reports", point.BucketCounts, wantCounts)
			break
		}
		_ = i
	}
	if point.Count != 10 {
		t.Errorf("Count = %d, want 10", point.Count)
	}
	if point.Sum != 1.5 {
		t.Errorf("Sum = %v, want 1.5", point.Sum)
	}
}

func TestClassicHistogramWithoutAnExplicitInfBucketStillGetsAnOverflowCount(t *testing.T) {
	metrics := produce(t, staticGatherer{families: []*dto.MetricFamily{
		classicHistogramFamily("podtrace_workload_dns_latency_seconds", 8, 2, map[float64]uint64{
			0.01: 3,
			0.1:  6,
		}),
	}})

	point := findMetric(t, metrics, "podtrace_workload_dns_latency_seconds").
		Data.(metricdata.Histogram[float64]).DataPoints[0]

	if len(point.BucketCounts) != 3 {
		t.Fatalf("BucketCounts = %v, want 3 entries for 2 bounds", point.BucketCounts)
	}
	if point.BucketCounts[2] != 2 {
		t.Errorf("overflow bucket = %d, want 2 (Count 8 minus the 6 below the last bound)",
			point.BucketCounts[2])
	}
}

func TestClassicHistogramBucketsAreSortedBeforeDifferencing(t *testing.T) {
	families := []*dto.MetricFamily{{
		Name: proto.String("podtrace_workload_dns_latency_seconds"),
		Type: dto.MetricType_HISTOGRAM.Enum(),
		Metric: []*dto.Metric{{
			Histogram: &dto.Histogram{
				SampleCount: proto.Uint64(9),
				SampleSum:   proto.Float64(1),
				Bucket: []*dto.Bucket{
					{UpperBound: proto.Float64(0.1), CumulativeCount: proto.Uint64(9)},
					{UpperBound: proto.Float64(0.001), CumulativeCount: proto.Uint64(4)},
					{UpperBound: proto.Float64(0.01), CumulativeCount: proto.Uint64(6)},
				},
			},
		}},
	}}

	point := findMetric(t, produce(t, staticGatherer{families: families}),
		"podtrace_workload_dns_latency_seconds").
		Data.(metricdata.Histogram[float64]).DataPoints[0]

	want := []uint64{4, 2, 3, 0}
	for i := range want {
		if point.BucketCounts[i] != want[i] {
			t.Fatalf("BucketCounts = %v (bounds %v), want %v; out-of-order input must be sorted "+
				"before differencing or the counts go negative and saturate to zero",
				point.BucketCounts, point.Bounds, want)
		}
	}
}

func TestBucketCountsNeverWrapWhenASnapshotRacesAnObservation(t *testing.T) {
	metrics := produce(t, staticGatherer{families: []*dto.MetricFamily{
		classicHistogramFamily("podtrace_workload_dns_latency_seconds", 1, 0.5, map[float64]uint64{
			0.01: 5,
			0.1:  3,
		}),
	}})

	point := findMetric(t, metrics, "podtrace_workload_dns_latency_seconds").
		Data.(metricdata.Histogram[float64]).DataPoints[0]

	for i, count := range point.BucketCounts {
		if count > 1_000_000 {
			t.Fatalf("BucketCounts[%d] = %d; an unsigned subtraction wrapped instead of saturating",
				i, count)
		}
	}
}

func TestClassicHistogramMatchesTheValuesActuallyObserved(t *testing.T) {
	reg := prometheus.NewRegistry()
	hist := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "podtrace_workload_probe_latency_seconds",
		Buckets: latencyBuckets,
	})
	if err := reg.Register(hist); err != nil {
		t.Fatalf("register: %v", err)
	}

	observations := []float64{0.0001, 0.002, 0.002, 0.03, 0.3, 60}
	for _, v := range observations {
		hist.Observe(v)
	}

	point := findMetric(t, produce(t, reg), "podtrace_workload_probe_latency_seconds").
		Data.(metricdata.Histogram[float64]).DataPoints[0]

	if point.Count != uint64(len(observations)) {
		t.Fatalf("Count = %d, want %d", point.Count, len(observations))
	}

	expected := make([]uint64, len(point.Bounds)+1)
	for _, v := range observations {
		slot := len(point.Bounds)
		for i, bound := range point.Bounds {
			if v <= bound {
				slot = i
				break
			}
		}
		expected[slot]++
	}
	for i := range expected {
		if point.BucketCounts[i] != expected[i] {
			t.Fatalf("BucketCounts = %v, want %v for observations %v with bounds %v",
				point.BucketCounts, expected, observations, point.Bounds)
		}
	}

	var total float64
	for _, v := range observations {
		total += v
	}
	if math.Abs(point.Sum-total) > 1e-9 {
		t.Errorf("Sum = %v, want %v", point.Sum, total)
	}
}

func TestNativeHistogramBucketsLandOnTheObservedValue(t *testing.T) {
	for _, observed := range []float64{0.0007, 0.004, 0.05, 1.5, 22} {
		t.Run(fmt.Sprintf("%g", observed), func(t *testing.T) {
			reg := prometheus.NewRegistry()
			hist := prometheus.NewHistogram(prometheus.HistogramOpts{
				Name:                           "podtrace_workload_probe_latency_seconds",
				NativeHistogramBucketFactor:    1.1,
				NativeHistogramMaxBucketNumber: 160,
			})
			if err := reg.Register(hist); err != nil {
				t.Fatalf("register: %v", err)
			}
			hist.Observe(observed)

			data := findMetric(t, produce(t, reg), "podtrace_workload_probe_latency_seconds").Data
			exp, ok := data.(metricdata.ExponentialHistogram[float64])
			if !ok {
				t.Fatalf("native histogram became %T, want ExponentialHistogram", data)
			}
			point := exp.DataPoints[0]
			if exp.Temporality != metricdata.CumulativeTemporality {
				t.Errorf("temporality = %v, want cumulative", exp.Temporality)
			}
			if point.Count != 1 {
				t.Fatalf("Count = %d, want 1", point.Count)
			}

			base := math.Pow(2, math.Pow(2, -float64(point.Scale)))
			var found bool
			for i, count := range point.PositiveBucket.Counts {
				if count == 0 {
					continue
				}
				index := point.PositiveBucket.Offset + int32(i)
				lower := math.Pow(base, float64(index))
				upper := math.Pow(base, float64(index+1))
				if observed > lower && observed <= upper {
					found = true
					continue
				}
				t.Errorf("observed %v landed in bucket index %d spanning (%g, %g]; a Prometheus "+
					"bucket index i covers (base^(i-1), base^i] and an OTLP index j covers "+
					"(base^j, base^(j+1)], so the offset must be the Prometheus index minus one",
					observed, index, lower, upper)
			}
			if !found {
				t.Errorf("no positive bucket carried the single observation %v; counts=%v offset=%d",
					observed, point.PositiveBucket.Counts, point.PositiveBucket.Offset)
			}
		})
	}
}

func TestNativeHistogramPreservesEveryObservation(t *testing.T) {
	reg := prometheus.NewRegistry()
	hist := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:                           "podtrace_workload_probe_latency_seconds",
		NativeHistogramBucketFactor:    1.1,
		NativeHistogramMaxBucketNumber: 160,
	})
	if err := reg.Register(hist); err != nil {
		t.Fatalf("register: %v", err)
	}

	observations := []float64{0, 0.0005, 0.0005, 0.004, 0.9, 0.9, 0.9, 12}
	var total float64
	for _, v := range observations {
		hist.Observe(v)
		total += v
	}

	point := findMetric(t, produce(t, reg), "podtrace_workload_probe_latency_seconds").
		Data.(metricdata.ExponentialHistogram[float64]).DataPoints[0]

	if point.Count != uint64(len(observations)) {
		t.Fatalf("Count = %d, want %d", point.Count, len(observations))
	}
	if math.Abs(point.Sum-total) > 1e-9 {
		t.Errorf("Sum = %v, want %v", point.Sum, total)
	}

	var bucketed uint64
	for _, c := range point.PositiveBucket.Counts {
		bucketed += c
	}
	for _, c := range point.NegativeBucket.Counts {
		bucketed += c
	}
	bucketed += point.ZeroCount
	if bucketed != point.Count {
		t.Errorf("buckets account for %d observations but Count is %d; a span gap was not "+
			"zero-filled or a delta was dropped (zero=%d positive=%v offset=%d)",
			bucketed, point.Count, point.ZeroCount, point.PositiveBucket.Counts,
			point.PositiveBucket.Offset)
	}
	if point.ZeroCount != 1 {
		t.Errorf("ZeroCount = %d, want 1; the single 0 observation belongs in the zero bucket",
			point.ZeroCount)
	}
}

func TestSparseSpansAreZeroFilledIntoOneContiguousRun(t *testing.T) {
	families := []*dto.MetricFamily{{
		Name: proto.String("podtrace_workload_probe_latency_seconds"),
		Type: dto.MetricType_HISTOGRAM.Enum(),
		Metric: []*dto.Metric{{
			Histogram: &dto.Histogram{
				SampleCount:   proto.Uint64(9),
				SampleSum:     proto.Float64(3),
				Schema:        proto.Int32(0),
				ZeroThreshold: proto.Float64(0),
				PositiveSpan: []*dto.BucketSpan{
					{Offset: proto.Int32(3), Length: proto.Uint32(2)},
					{Offset: proto.Int32(2), Length: proto.Uint32(1)},
				},
				PositiveDelta: []int64{4, -2, 3},
			},
		}},
	}}

	point := findMetric(t, produce(t, staticGatherer{families: families}),
		"podtrace_workload_probe_latency_seconds").
		Data.(metricdata.ExponentialHistogram[float64]).DataPoints[0]

	if point.PositiveBucket.Offset != 2 {
		t.Errorf("Offset = %d, want 2 (first Prometheus index 3, minus one)",
			point.PositiveBucket.Offset)
	}
	want := []uint64{4, 2, 0, 0, 5}
	if len(point.PositiveBucket.Counts) != len(want) {
		t.Fatalf("Counts = %v, want %v", point.PositiveBucket.Counts, want)
	}
	for i := range want {
		if point.PositiveBucket.Counts[i] != want[i] {
			t.Fatalf("Counts = %v, want %v; indices 3,4 then 7 must become a contiguous run with "+
				"explicit zeros for 5 and 6", point.PositiveBucket.Counts, want)
		}
	}
}

func TestZeroLengthSpanOffsetStillAdvancesTheIndex(t *testing.T) {
	spans := []*dto.BucketSpan{
		{Offset: proto.Int32(1), Length: proto.Uint32(1)},
		{Offset: proto.Int32(2), Length: proto.Uint32(0)},
		{Offset: proto.Int32(3), Length: proto.Uint32(1)},
	}
	decoded, ok := decodeSpans(spans, []int64{1, 0}, nil)
	if !ok {
		t.Fatal("decodeSpans refused a valid encoding")
	}
	if len(decoded) != 2 {
		t.Fatalf("decoded %d buckets, want 2", len(decoded))
	}
	if decoded[0].index != 1 {
		t.Errorf("first index = %d, want 1", decoded[0].index)
	}
	if decoded[1].index != 7 {
		t.Errorf("second index = %d, want 7 (1 + 1 + 2 + 3); a zero-length span's offset must "+
			"still accumulate", decoded[1].index)
	}
}

func TestNegativeObservationsFillTheNegativeBucket(t *testing.T) {
	families := []*dto.MetricFamily{{
		Name: proto.String("podtrace_workload_probe_delta_seconds"),
		Type: dto.MetricType_HISTOGRAM.Enum(),
		Metric: []*dto.Metric{{
			Histogram: &dto.Histogram{
				SampleCount:   proto.Uint64(3),
				SampleSum:     proto.Float64(-1),
				Schema:        proto.Int32(0),
				NegativeSpan:  []*dto.BucketSpan{{Offset: proto.Int32(1), Length: proto.Uint32(1)}},
				NegativeDelta: []int64{3},
			},
		}},
	}}

	point := findMetric(t, produce(t, staticGatherer{families: families}),
		"podtrace_workload_probe_delta_seconds").
		Data.(metricdata.ExponentialHistogram[float64]).DataPoints[0]

	if point.NegativeBucket.Offset != 0 || len(point.NegativeBucket.Counts) != 1 ||
		point.NegativeBucket.Counts[0] != 3 {
		t.Errorf("negative bucket = %+v, want offset 0 with a single count of 3",
			point.NegativeBucket)
	}
}

func TestNativeHistogramWithOnlyZeroObservationsIsStillExponential(t *testing.T) {
	families := []*dto.MetricFamily{{
		Name: proto.String("podtrace_workload_probe_latency_seconds"),
		Type: dto.MetricType_HISTOGRAM.Enum(),
		Metric: []*dto.Metric{{
			Histogram: &dto.Histogram{
				SampleCount:   proto.Uint64(4),
				SampleSum:     proto.Float64(0),
				Schema:        proto.Int32(3),
				ZeroThreshold: proto.Float64(1e-128),
				ZeroCount:     proto.Uint64(4),
			},
		}},
	}}

	data := findMetric(t, produce(t, staticGatherer{families: families}),
		"podtrace_workload_probe_latency_seconds").Data
	exp, ok := data.(metricdata.ExponentialHistogram[float64])
	if !ok {
		t.Fatalf("became %T, want ExponentialHistogram; a native histogram with no spans still "+
			"has a schema and no classic buckets to fall back on", data)
	}
	if exp.DataPoints[0].ZeroCount != 4 {
		t.Errorf("ZeroCount = %d, want 4", exp.DataPoints[0].ZeroCount)
	}
}

func TestUnrepresentableSchemaIsSkippedRatherThanGuessed(t *testing.T) {
	families := []*dto.MetricFamily{{
		Name: proto.String("podtrace_workload_custom_bounds_seconds"),
		Type: dto.MetricType_HISTOGRAM.Enum(),
		Metric: []*dto.Metric{{
			Histogram: &dto.Histogram{
				SampleCount:   proto.Uint64(1),
				SampleSum:     proto.Float64(1),
				Schema:        proto.Int32(-53),
				PositiveSpan:  []*dto.BucketSpan{{Offset: proto.Int32(0), Length: proto.Uint32(1)}},
				PositiveDelta: []int64{1},
			},
		}},
	}}

	if metrics := produce(t, staticGatherer{families: families}); len(metrics) != 0 {
		t.Errorf("produced %+v; schema -53 is custom-bucket layout, not the base-2^(2^-scale) "+
			"layout OTLP exponential histograms describe, so emitting it would report wrong "+
			"boundaries", metrics)
	}
}

func TestInconsistentSpanEncodingIsRefused(t *testing.T) {
	if _, ok := decodeSpans(
		[]*dto.BucketSpan{{Offset: proto.Int32(0), Length: proto.Uint32(4)}},
		[]int64{1, 1},
		nil,
	); ok {
		t.Error("decodeSpans accepted spans claiming 4 buckets with only 2 deltas")
	}
	if _, ok := decodeSpans(
		[]*dto.BucketSpan{{Offset: proto.Int32(0), Length: proto.Uint32(1)}},
		[]int64{-5},
		nil,
	); ok {
		t.Error("decodeSpans accepted a delta encoding whose running count goes negative")
	}
	if _, ok := decodeSpans([]*dto.BucketSpan{nil}, []int64{1}, nil); ok {
		t.Error("decodeSpans accepted a nil span")
	}
	if _, ok := decodeSpans(
		[]*dto.BucketSpan{{Offset: proto.Int32(0), Length: proto.Uint32(1)}},
		nil,
		[]float64{math.NaN()},
	); ok {
		t.Error("decodeSpans accepted a NaN float count")
	}
}

func TestFloatNativeHistogramUsesAbsoluteCounts(t *testing.T) {
	decoded, ok := decodeSpans(
		[]*dto.BucketSpan{{Offset: proto.Int32(2), Length: proto.Uint32(2)}},
		nil,
		[]float64{3, 5},
	)
	if !ok {
		t.Fatal("decodeSpans refused a float histogram")
	}
	if decoded[0].count != 3 || decoded[1].count != 5 {
		t.Errorf("counts = %d,%d, want 3,5; float histograms carry counts outright, not as deltas",
			decoded[0].count, decoded[1].count)
	}
}

func TestFloatSampleAndBucketCountsAreRead(t *testing.T) {
	families := []*dto.MetricFamily{{
		Name: proto.String("podtrace_workload_probe_latency_seconds"),
		Type: dto.MetricType_HISTOGRAM.Enum(),
		Metric: []*dto.Metric{{
			Histogram: &dto.Histogram{
				SampleCountFloat: proto.Float64(6),
				SampleSum:        proto.Float64(1),
				Bucket: []*dto.Bucket{
					{UpperBound: proto.Float64(0.01), CumulativeCountFloat: proto.Float64(4)},
				},
			},
		}},
	}}

	point := findMetric(t, produce(t, staticGatherer{families: families}),
		"podtrace_workload_probe_latency_seconds").
		Data.(metricdata.Histogram[float64]).DataPoints[0]

	if point.Count != 6 {
		t.Errorf("Count = %d, want 6 from SampleCountFloat", point.Count)
	}
	if point.BucketCounts[0] != 4 || point.BucketCounts[1] != 2 {
		t.Errorf("BucketCounts = %v, want [4 2] from CumulativeCountFloat", point.BucketCounts)
	}
}

func TestSummaryAndUntypedFamiliesAreSkipped(t *testing.T) {
	families := []*dto.MetricFamily{
		{
			Name:   proto.String("podtrace_workload_summary_seconds"),
			Type:   dto.MetricType_SUMMARY.Enum(),
			Metric: []*dto.Metric{{Summary: &dto.Summary{SampleCount: proto.Uint64(1)}}},
		},
		{
			Name:   proto.String("podtrace_workload_untyped"),
			Type:   dto.MetricType_UNTYPED.Enum(),
			Metric: []*dto.Metric{{Untyped: &dto.Untyped{Value: proto.Float64(1)}}},
		},
		counterFamily("podtrace_workload_errors_total", 1),
	}

	metrics := produce(t, staticGatherer{families: families})
	if len(metrics) != 1 || metrics[0].Name != "podtrace_workload_errors_total" {
		t.Errorf("produced %+v; a summary has no reconstructible histogram and an untyped family "+
			"could be either kind, so both must be skipped rather than guessed", metrics)
	}
}

func TestEmptyAndMalformedFamiliesAreSkipped(t *testing.T) {
	families := []*dto.MetricFamily{
		nil,
		{Name: proto.String("podtrace_workload_empty_total"), Type: dto.MetricType_COUNTER.Enum()},
		{
			Name:   proto.String("podtrace_workload_typeless_total"),
			Type:   dto.MetricType_COUNTER.Enum(),
			Metric: []*dto.Metric{{}},
		},
	}

	metrics := produce(t, staticGatherer{families: families})
	for _, m := range metrics {
		if sum, ok := m.Data.(metricdata.Sum[float64]); ok && len(sum.DataPoints) != 0 {
			t.Errorf("%s produced data points from a metric with no counter", m.Name)
		}
	}
}

func TestConventionFamiliesGetTheirDottedOTLPNames(t *testing.T) {
	families := []*dto.MetricFamily{{
		Name: proto.String(semconvHTTPDuration),
		Type: dto.MetricType_HISTOGRAM.Enum(),
		Metric: []*dto.Metric{{
			Label: labelPairs(
				"service_name", "checkout",
				"k8s_namespace_name", "shop",
				"k8s_container_name", "web",
				"http_request_method", "GET",
				"http_response_status_code", "200",
				"network_protocol_name", "http/1.1",
			),
			Histogram: &dto.Histogram{
				SampleCount: proto.Uint64(1),
				SampleSum:   proto.Float64(0.01),
				Bucket:      []*dto.Bucket{{UpperBound: proto.Float64(0.1), CumulativeCount: proto.Uint64(1)}},
			},
		}},
	}}

	m := findMetric(t, produce(t, staticGatherer{families: families}),
		"http.server.request.duration")
	if m.Unit != "s" {
		t.Errorf("unit = %q, want s", m.Unit)
	}

	attrs := m.Data.(metricdata.Histogram[float64]).DataPoints[0].Attributes
	want := map[string]string{
		"service.name":              "checkout",
		"k8s.namespace.name":        "shop",
		"k8s.container.name":        "web",
		"http.request.method":       "GET",
		"http.response.status_code": "200",
		"network.protocol.name":     "http/1.1",
	}
	for key, value := range want {
		got, ok := attrs.Value(attribute.Key(key))
		if !ok {
			t.Errorf("attribute %q missing; over OTLP a convention family must carry the "+
				"convention's own dotted keys or a stock backend does not recognise it", key)
			continue
		}
		if got.AsString() != value {
			t.Errorf("attribute %q = %q, want %q", key, got.AsString(), value)
		}
	}
	if _, ok := attrs.Value("http_request_method"); ok {
		t.Error("the Prometheus label name survived alongside the dotted key")
	}
}

func TestStatusCodeKeepsItsConventionalUnderscore(t *testing.T) {
	if got := semconvAttributeKey("http_response_status_code"); got != "http.response.status_code" {
		t.Errorf("got %q, want http.response.status_code; replacing every underscore with a dot "+
			"would produce http.response.status.code, which is not the convention's key", got)
	}
}

func TestEveryConventionLabelHasAnOTLPKey(t *testing.T) {
	collectors := newSemconvCollectors(false, 10)
	for _, collector := range collectors.all() {
		for _, label := range collectorLabelNames(t, collector) {
			if _, ok := semconvOTLPAttributeKeys[label]; !ok {
				t.Errorf("convention label %q has no entry in semconvOTLPAttributeKeys, so over "+
					"OTLP it would ship with its Prometheus name", label)
			}
		}
	}
}

func TestEveryConventionFamilyHasAnOTLPName(t *testing.T) {
	for _, name := range []string{semconvHTTPDuration, semconvRPCDuration, semconvDBDuration} {
		identity, ok := semconvOTLPFamilies[name]
		if !ok {
			t.Errorf("convention family %q has no OTLP name", name)
			continue
		}
		if identity.name == name {
			t.Errorf("family %q maps to itself; the OTLP name must be the dotted form", name)
		}
	}
}

func TestPodtraceFamiliesKeepTheirPrometheusNames(t *testing.T) {
	name, unit := otlpIdentityFor("podtrace_workload_network_bytes_total")
	if name != "podtrace_workload_network_bytes_total" {
		t.Errorf("name = %q; podtrace's own names have no convention to honour, so guessing "+
			"where dots go would invent a name nobody queries", name)
	}
	if unit != "By" {
		t.Errorf("unit = %q, want By", unit)
	}
}

func TestUnitsComeFromTheConventionalSuffix(t *testing.T) {
	cases := map[string]string{
		"podtrace_workload_dns_latency_seconds":    "s",
		"podtrace_workload_network_bytes_total":    "By",
		"podtrace_workload_l7_requests_total":      "",
		"podtrace_workload_metrics_series_active":  "",
		"podtrace_workload_cpu_blocked_seconds":    "s",
		"podtrace_workload_filesystem_bytes_total": "By",
	}
	for name, want := range cases {
		if _, got := otlpIdentityFor(name); got != want {
			t.Errorf("%s unit = %q, want %q", name, got, want)
		}
	}
}

func TestCreatedTimestampBecomesTheStartTime(t *testing.T) {
	created := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	families := []*dto.MetricFamily{{
		Name: proto.String("podtrace_workload_errors_total"),
		Type: dto.MetricType_COUNTER.Enum(),
		Metric: []*dto.Metric{{Counter: &dto.Counter{
			Value:            proto.Float64(3),
			CreatedTimestamp: timestamppb.New(created),
		}}},
	}}

	point := findMetric(t, produce(t, staticGatherer{families: families}),
		"podtrace_workload_errors_total").
		Data.(metricdata.Sum[float64]).DataPoints[0]

	if !point.StartTime.Equal(created) {
		t.Errorf("StartTime = %v, want the created timestamp %v; a wrong start makes a backend "+
			"compute rates over the wrong window", point.StartTime, created)
	}
}

func TestMissingCreatedTimestampFallsBackToProducerStart(t *testing.T) {
	producer := NewProducer(staticGatherer{families: []*dto.MetricFamily{
		counterFamily("podtrace_workload_errors_total", 1),
	}})

	scopes, err := producer.Produce(context.Background())
	if err != nil {
		t.Fatalf("Produce: %v", err)
	}
	point := scopes[0].Metrics[0].Data.(metricdata.Sum[float64]).DataPoints[0]
	if !point.StartTime.Equal(producer.start) {
		t.Errorf("StartTime = %v, want the producer start %v; no series in the registry predates "+
			"it, so it is the safe floor", point.StartTime, producer.start)
	}
}

func TestGatherErrorsSurfaceRatherThanEmittingNothingQuietly(t *testing.T) {
	if _, err := NewProducer(failingGatherer{}).Produce(context.Background()); err == nil {
		t.Error("Produce swallowed a gather error; a silently empty export looks like an idle node")
	}
}

func TestNilProducerAndEmptyRegistryAreInert(t *testing.T) {
	var nilProducer *Producer
	if scopes, err := nilProducer.Produce(context.Background()); err != nil || scopes != nil {
		t.Errorf("nil Producer returned (%v, %v), want (nil, nil)", scopes, err)
	}
	if scopes, err := (&Producer{}).Produce(context.Background()); err != nil || scopes != nil {
		t.Errorf("Producer with no gatherer returned (%v, %v), want (nil, nil)", scopes, err)
	}
	if scopes, err := NewProducer(prometheus.NewRegistry()).Produce(context.Background()); err != nil || scopes != nil {
		t.Errorf("empty registry returned (%v, %v), want (nil, nil)", scopes, err)
	}
}

func TestFloatToCountAndSaturatingSubEdges(t *testing.T) {
	if got := floatToCount(-1); got != 0 {
		t.Errorf("floatToCount(-1) = %d, want 0", got)
	}
	if got := floatToCount(math.NaN()); got != 0 {
		t.Errorf("floatToCount(NaN) = %d, want 0", got)
	}
	if got := floatToCount(math.Inf(1)); got != math.MaxUint64 {
		t.Errorf("floatToCount(+Inf) = %d, want MaxUint64", got)
	}
	if got := floatToCount(7.9); got != 7 {
		t.Errorf("floatToCount(7.9) = %d, want 7", got)
	}
	if got := saturatingSub(3, 9); got != 0 {
		t.Errorf("saturatingSub(3, 9) = %d, want 0", got)
	}
	if got := saturatingSub(9, 3); got != 6 {
		t.Errorf("saturatingSub(9, 3) = %d, want 6", got)
	}
}

func TestIsNativeHistogramDistinguishesTheRepresentations(t *testing.T) {
	if isNativeHistogram(nil) {
		t.Error("nil histogram reported as native")
	}
	classic := &dto.Histogram{Bucket: []*dto.Bucket{{UpperBound: proto.Float64(1)}}}
	if isNativeHistogram(classic) {
		t.Error("a histogram with only classic buckets reported as native")
	}
	dual := &dto.Histogram{
		Bucket:       []*dto.Bucket{{UpperBound: proto.Float64(1)}},
		Schema:       proto.Int32(3),
		PositiveSpan: []*dto.BucketSpan{{Offset: proto.Int32(0), Length: proto.Uint32(1)}},
	}
	if !isNativeHistogram(dual) {
		t.Error("a histogram carrying both representations must prefer the native one")
	}
}

func TestSinkGathersOnlyItsOwnFamilies(t *testing.T) {
	shared := prometheus.NewRegistry()
	shared.MustRegister(prometheus.NewCounter(prometheus.CounterOpts{
		Name: "podtrace_agent_unrelated_total",
	}))

	sink, err := New(shared, Options{SemanticConventions: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	families, err := sink.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, family := range families {
		if family.GetName() == "podtrace_agent_unrelated_total" {
			t.Fatal("Gather returned a family from the shared registry; the OTLP producer must " +
				"ship the workload surface and nothing else")
		}
	}
	if len(families) == 0 {
		t.Fatal("Gather returned nothing; the sink's own collectors are not registered")
	}
}

func TestNilSinkGatherIsInert(t *testing.T) {
	var sink *Sink
	if families, err := sink.Gather(); err != nil || families != nil {
		t.Errorf("nil Sink Gather returned (%v, %v), want (nil, nil)", families, err)
	}
}

func TestProducerOverTheRealSinkCoversTheWholeSurface(t *testing.T) {
	sink, err := New(prometheus.NewRegistry(), Options{SemanticConventions: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := sink.Export(context.Background(), surfaceExercisingBatch()); err != nil {
		t.Fatalf("Export: %v", err)
	}

	metrics := produce(t, sink)
	if len(metrics) == 0 {
		t.Fatal("the producer emitted nothing for an exercised sink")
	}
	for _, m := range metrics {
		switch data := m.Data.(type) {
		case metricdata.Sum[float64]:
			if data.Temporality != metricdata.CumulativeTemporality {
				t.Errorf("%s sum is %v, want cumulative", m.Name, data.Temporality)
			}
		case metricdata.Histogram[float64]:
			if data.Temporality != metricdata.CumulativeTemporality {
				t.Errorf("%s histogram is %v, want cumulative", m.Name, data.Temporality)
			}
			for _, point := range data.DataPoints {
				if len(point.BucketCounts) != len(point.Bounds)+1 {
					t.Errorf("%s has %d counts for %d bounds", m.Name,
						len(point.BucketCounts), len(point.Bounds))
				}
			}
		case metricdata.Gauge[float64]:
		default:
			t.Errorf("%s produced unexpected aggregation %T", m.Name, data)
		}
	}
	for _, name := range []string{
		"http.server.request.duration",
		"rpc.server.duration",
		"db.client.operation.duration",
	} {
		findMetric(t, metrics, name)
	}
}

func TestMetricsWithNoPayloadAreSkippedWithinAFamily(t *testing.T) {
	families := []*dto.MetricFamily{
		{
			Name: proto.String("podtrace_workload_metrics_series_active"),
			Type: dto.MetricType_GAUGE.Enum(),
			Metric: []*dto.Metric{
				{},
				{Gauge: &dto.Gauge{Value: proto.Float64(5)}},
			},
		},
		{
			Name: proto.String("podtrace_workload_dns_latency_seconds"),
			Type: dto.MetricType_HISTOGRAM.Enum(),
			Metric: []*dto.Metric{
				{Histogram: &dto.Histogram{
					SampleCount: proto.Uint64(1),
					Bucket:      []*dto.Bucket{{UpperBound: proto.Float64(1), CumulativeCount: proto.Uint64(1)}},
				}},
				{},
			},
		},
	}

	metrics := produce(t, staticGatherer{families: families})

	gauge := findMetric(t, metrics, "podtrace_workload_metrics_series_active").
		Data.(metricdata.Gauge[float64])
	if len(gauge.DataPoints) != 1 || gauge.DataPoints[0].Value != 5 {
		t.Errorf("gauge points = %+v, want only the one with a value", gauge.DataPoints)
	}

	hist := findMetric(t, metrics, "podtrace_workload_dns_latency_seconds").
		Data.(metricdata.Histogram[float64])
	if len(hist.DataPoints) != 1 {
		t.Errorf("histogram points = %d, want 1", len(hist.DataPoints))
	}
}

func TestAnUndecodableSideSkipsTheWholeFamily(t *testing.T) {
	for name, histogram := range map[string]*dto.Histogram{
		"positive": {
			SampleCount:   proto.Uint64(1),
			Schema:        proto.Int32(0),
			PositiveSpan:  []*dto.BucketSpan{{Offset: proto.Int32(0), Length: proto.Uint32(3)}},
			PositiveDelta: []int64{1},
		},
		"negative": {
			SampleCount:   proto.Uint64(1),
			Schema:        proto.Int32(0),
			PositiveSpan:  []*dto.BucketSpan{{Offset: proto.Int32(0), Length: proto.Uint32(1)}},
			PositiveDelta: []int64{1},
			NegativeSpan:  []*dto.BucketSpan{{Offset: proto.Int32(0), Length: proto.Uint32(3)}},
			NegativeDelta: []int64{1},
		},
	} {
		t.Run(name, func(t *testing.T) {
			families := []*dto.MetricFamily{{
				Name:   proto.String("podtrace_workload_probe_latency_seconds"),
				Type:   dto.MetricType_HISTOGRAM.Enum(),
				Metric: []*dto.Metric{{Histogram: histogram}},
			}}
			if metrics := produce(t, staticGatherer{families: families}); len(metrics) != 0 {
				t.Errorf("produced %+v from an inconsistent %s encoding; a half-read histogram "+
					"reports wrong boundaries, which is worse than a missing metric", metrics, name)
			}
		})
	}
}

func TestSpansThatDecodeToNoBucketsProduceAnEmptyRun(t *testing.T) {
	bucket, ok := exponentialBucket(
		[]*dto.BucketSpan{{Offset: proto.Int32(4), Length: proto.Uint32(0)}},
		nil,
		nil,
	)
	if !ok {
		t.Fatal("exponentialBucket refused spans of length zero")
	}
	if len(bucket.Counts) != 0 || bucket.Offset != 0 {
		t.Errorf("bucket = %+v, want the zero value; there are no buckets to describe", bucket)
	}
}

func TestSpansThatConsumeFewerCountsThanSuppliedAreRefused(t *testing.T) {
	if _, ok := decodeSpans(
		[]*dto.BucketSpan{{Offset: proto.Int32(0), Length: proto.Uint32(1)}},
		[]int64{1, 1, 1},
		nil,
	); ok {
		t.Error("decodeSpans accepted 3 deltas for spans covering 1 bucket; leftover counts mean " +
			"the spans and deltas do not describe the same histogram")
	}
}

func TestUnmappedConventionLabelsPassThroughUnchanged(t *testing.T) {
	if got := semconvAttributeKey("some_future_label"); got != "some_future_label" {
		t.Errorf("got %q, want the label unchanged; a label with no table entry must ship as it "+
			"is rather than being mangled", got)
	}
}
