package inspect

import (
	"errors"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
)

func TestDeltaMeanReportsNothingWithoutObservations(t *testing.T) {

	if _, ok := (Delta{Count: 0, Sum: 5}).Mean(); ok {
		t.Error("a delta with no observations reported a mean")
	}
	if _, ok := (Delta{Reset: true, Count: 10, Sum: 5}).Mean(); ok {
		t.Error("a delta across a counter reset reported a mean; the numbers span " +
			"two different process lifetimes")
	}
	got, ok := (Delta{Count: 4, Sum: 2}).Mean()
	if !ok || got != 0.5 {
		t.Errorf("Mean() = %v,%v; want 0.5,true", got, ok)
	}
}

func TestDeltaPerSecondGuardsResetsAndZeroIntervals(t *testing.T) {
	if got := (Delta{Value: 100, Reset: true}).PerSecond(time.Minute); got != 0 {
		t.Errorf("rate across a reset = %v, want 0", got)
	}
	if got := (Delta{Value: 100}).PerSecond(0); got != 0 {
		t.Errorf("rate over a zero interval = %v, want 0 rather than +Inf", got)
	}
	if got := (Delta{Value: 120}).PerSecond(time.Minute); got != 2 {
		t.Errorf("rate = %v, want 2/s", got)
	}
}

func TestDeltasAndGaugesReturnNothingForAnAbsentFamily(t *testing.T) {

	w := Window{}
	if got := w.Deltas("podtrace_workload_does_not_exist"); got != nil {
		t.Errorf("Deltas on an absent family = %v, want nil", got)
	}
	if got := w.Gauges("podtrace_workload_does_not_exist"); got != nil {
		t.Errorf("Gauges on an absent family = %v, want nil", got)
	}
}

func TestSortedKeysIsEmptyForAnEmptyLabelSet(t *testing.T) {
	if got := sortedKeys(nil); got != nil {
		t.Errorf("sortedKeys(nil) = %v, want nil", got)
	}
	if got := sortedKeys(map[string]string{}); got != nil {
		t.Errorf("sortedKeys(empty) = %v, want nil", got)
	}
}

func TestSampleLabelReadsFamilySpecificLabels(t *testing.T) {
	s := Sample{Labels: map[string]string{"resource": "cpu"}}
	if got := s.Label("resource"); got != "cpu" {
		t.Errorf("Label(resource) = %q", got)
	}
	if got := s.Label("absent"); got != "" {
		t.Errorf("Label(absent) = %q, want empty", got)
	}
}

func TestAnUntypedMetricIsStillReadable(t *testing.T) {

	name := "podtrace_workload_untyped_example"
	value := 42.0
	typ := dto.MetricType_UNTYPED
	snap, err := Take(&fixedGatherer{families: []*dto.MetricFamily{{
		Name: &name, Type: &typ,
		Metric: []*dto.Metric{{
			Label:   workloadLabels(),
			Untyped: &dto.Untyped{Value: &value},
		}},
	}}}, time.Now())
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	samples := snap.Family(name)
	if len(samples) != 1 {
		t.Fatalf("got %d samples", len(samples))
	}
	if samples[0].Value != value {
		t.Errorf("untyped value = %v, want %v", samples[0].Value, value)
	}
}

type stubSource struct {
	families map[string][]*dto.Metric
	names    []string
}

func (s stubSource) CollectFamilies([]string) map[string][]*dto.Metric { return s.families }

func (s stubSource) RuleFamilies() []string { return s.names }

func TestTakeFromReadsOnlyTheRequestedFamilies(t *testing.T) {
	counterValue := 12.0
	src := stubSource{
		names: []string{familyL7Requests},
		families: map[string][]*dto.Metric{
			familyL7Requests: {{
				Label:   workloadLabels(label("outcome", "ok")),
				Counter: &dto.Counter{Value: &counterValue},
			}},
		},
	}

	snap := TakeFrom(src, time.Now())
	if snap.IsZero() {
		t.Fatal("TakeFrom produced an empty snapshot")
	}
	samples := snap.Family(familyL7Requests)
	if len(samples) != 1 {
		t.Fatalf("got %d samples, want 1", len(samples))
	}
	if samples[0].Value != counterValue {
		t.Errorf("value = %v, want %v", samples[0].Value, counterValue)
	}
	if samples[0].Workload != "checkout" {
		t.Errorf("workload = %q, want the identity lifted off the labels", samples[0].Workload)
	}
	if got := snap.Family(familyUtilization); got != nil {
		t.Errorf("a family the source did not serve resolved to %v, want nil", got)
	}
}

func TestTakeFromOnAnEmptySourceIsUsableNotZero(t *testing.T) {
	snap := TakeFrom(stubSource{}, time.Now())
	if snap.IsZero() {
		t.Error("a source with no series produced a zero snapshot; the next pass would " +
			"then read every counter's lifetime total as one interval's worth")
	}
	if got := snap.Family(familyL7Requests); got != nil {
		t.Errorf("Family on an empty snapshot = %v, want nil", got)
	}
}

func TestAnEngineWithASourcePrefersItOverTheGatherer(t *testing.T) {
	// Both are set. The source must win, because the whole point is not
	// serialising the registry every interval.
	utilisation := 97.0
	src := stubSource{
		names: []string{familyUtilization},
		families: map[string][]*dto.Metric{
			familyUtilization: {{
				Label: workloadLabels(label("resource", "cpu")),
				Gauge: &dto.Gauge{Value: &utilisation},
			}},
		},
	}
	clock := time.Now()
	engine, err := New(Options{
		Source:     src,
		Gatherer:   &fixedGatherer{err: errors.New("the gatherer must not be consulted")},
		Rules:      []Rule{saturationRule()},
		Thresholds: DefaultThresholds(),
		Now:        func() time.Time { return clock },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := engine.Evaluate(); err != nil {
		t.Fatalf("Evaluate consulted the gatherer: %v", err)
	}
	clock = clock.Add(2 * time.Minute)
	activated, err := engine.Evaluate()
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(activated) != 1 {
		t.Fatalf("activated %d issues from the source's samples, want 1", len(activated))
	}
}
