package inspect

import (
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/diagnose/detector"
)

type recorder struct {
	activated []detector.Issue
	cleared   []detector.Issue
}

func (r *recorder) IssueActivated(i detector.Issue) { r.activated = append(r.activated, i) }
func (r *recorder) IssueCleared(i detector.Issue)   { r.cleared = append(r.cleared, i) }

type fixedGatherer struct {
	families []*dto.MetricFamily
	err      error
}

func (g *fixedGatherer) Gather() ([]*dto.MetricFamily, error) { return g.families, g.err }

func label(name, value string) *dto.LabelPair {
	return &dto.LabelPair{Name: &name, Value: &value}
}

func counterFamily(name string, metrics ...*dto.Metric) *dto.MetricFamily {
	t := dto.MetricType_COUNTER
	n := name
	return &dto.MetricFamily{Name: &n, Type: &t, Metric: metrics}
}

func gaugeFamily(name string, metrics ...*dto.Metric) *dto.MetricFamily {
	t := dto.MetricType_GAUGE
	n := name
	return &dto.MetricFamily{Name: &n, Type: &t, Metric: metrics}
}

func histogramFamily(name string, metrics ...*dto.Metric) *dto.MetricFamily {
	t := dto.MetricType_HISTOGRAM
	n := name
	return &dto.MetricFamily{Name: &n, Type: &t, Metric: metrics}
}

func counter(value float64, labels ...*dto.LabelPair) *dto.Metric {
	v := value
	return &dto.Metric{Label: labels, Counter: &dto.Counter{Value: &v}}
}

func gauge(value float64, labels ...*dto.LabelPair) *dto.Metric {
	v := value
	return &dto.Metric{Label: labels, Gauge: &dto.Gauge{Value: &v}}
}

func histogram(count uint64, sum float64, labels ...*dto.LabelPair) *dto.Metric {
	c, s := count, sum
	return &dto.Metric{Label: labels, Histogram: &dto.Histogram{SampleCount: &c, SampleSum: &s}}
}

func workloadLabels(extra ...*dto.LabelPair) []*dto.LabelPair {
	base := []*dto.LabelPair{
		label("namespace", "shop"),
		label("workload", "checkout"),
		label("workload_kind", "Deployment"),
		label("container", "app"),
	}
	return append(base, extra...)
}

type harness struct {
	engine   *Engine
	gatherer *fixedGatherer
	registry *prometheus.Registry
	observer *recorder
	clock    time.Time
}

func newHarness(t *testing.T, rules ...Rule) *harness {
	t.Helper()
	h := &harness{
		gatherer: &fixedGatherer{},
		registry: prometheus.NewRegistry(),
		observer: &recorder{},
		clock:    time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC),
	}
	if rules == nil {
		rules = Rules()
	}
	engine, err := New(Options{
		Gatherer:   h.gatherer,
		Registerer: h.registry,
		Rules:      rules,
		Thresholds: DefaultThresholds(),
		Observer:   h.observer,
		Now:        func() time.Time { return h.clock },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.engine = engine
	return h
}

func (h *harness) serve(families ...*dto.MetricFamily) { h.gatherer.families = families }

func (h *harness) advance(d time.Duration) { h.clock = h.clock.Add(d) }

func (h *harness) evaluate(t *testing.T) []detector.Issue {
	t.Helper()
	activated, err := h.engine.Evaluate()
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return activated
}

func (h *harness) activeGauges(t *testing.T) []map[string]string {
	t.Helper()
	families, err := h.registry.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	var out []map[string]string
	for _, f := range families {
		if f.GetName() != "podtrace_issue_active" {
			continue
		}
		for _, m := range f.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			labels["__value"] = formatFloat(m.GetGauge().GetValue())
			out = append(out, labels)
		}
	}
	return out
}

func formatFloat(f float64) string {
	if f == 1 {
		return "1"
	}
	return "not-1"
}

func (h *harness) counterValue(t *testing.T, name string, match map[string]string) float64 {
	t.Helper()
	families, err := h.registry.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
	metric:
		for _, m := range f.GetMetric() {
			for k, want := range match {
				found := false
				for _, l := range m.GetLabel() {
					if l.GetName() == k && l.GetValue() == want {
						found = true
					}
				}
				if !found {
					continue metric
				}
			}
			return m.GetCounter().GetValue()
		}
	}
	return 0
}

func saturated(pct float64, resource, pod string) *dto.MetricFamily {
	return gaugeFamily(familyUtilization,
		gauge(pct, workloadLabels(label("resource", resource), label("pod", pod))...))
}

func TestAnIssueOnlyFiresOnceItsConditionHasHeld(t *testing.T) {
	h := newHarness(t, saturationRule())
	h.serve(saturated(97, "cpu", "checkout-a"))

	if got := h.evaluate(t); len(got) != 0 {
		t.Fatalf("activated %v on the first tick; a single reading is not yet an issue, and "+
			"without a hold time one scrape-interval blip pages someone", got)
	}
	if got := h.activeGauges(t); len(got) != 0 {
		t.Errorf("the gauge went to 1 before the For elapsed: %v", got)
	}

	h.advance(30 * time.Second)
	if got := h.evaluate(t); len(got) != 0 {
		t.Fatalf("activated after 30s with a For of 1m: %v", got)
	}

	h.advance(45 * time.Second)
	activated := h.evaluate(t)
	if len(activated) != 1 {
		t.Fatalf("activated %d issues after the For elapsed, want 1", len(activated))
	}
	if activated[0].ID != detector.IDResourceSaturation {
		t.Errorf("activated %q, want resource.saturation", activated[0].ID)
	}
	if activated[0].Subject.Pod != "checkout-a" {
		t.Errorf("subject pod = %q; without it the issue cannot start a session",
			activated[0].Subject.Pod)
	}
}

func TestAnAlreadyActiveIssueDoesNotReactivateEveryTick(t *testing.T) {
	h := newHarness(t, saturationRule())
	h.serve(saturated(97, "cpu", "checkout-a"))
	h.evaluate(t)
	h.advance(2 * time.Minute)
	if len(h.evaluate(t)) != 1 {
		t.Fatal("the issue never activated")
	}

	for i := 0; i < 5; i++ {
		h.advance(time.Minute)
		if got := h.evaluate(t); len(got) != 0 {
			t.Fatalf("tick %d re-activated %v; a sustained issue would start a session on "+
				"every evaluation", i, got)
		}
	}
	if len(h.observer.activated) != 1 {
		t.Errorf("the observer saw %d activations, want 1", len(h.observer.activated))
	}
}

func TestAResolvedConditionClearsTheIssueAndItsSeries(t *testing.T) {
	h := newHarness(t, saturationRule())
	h.serve(saturated(97, "cpu", "checkout-a"))
	h.evaluate(t)
	h.advance(2 * time.Minute)
	h.evaluate(t)

	h.advance(time.Minute)
	h.serve(saturated(12, "cpu", "checkout-a"))
	h.evaluate(t)

	if len(h.observer.cleared) != 1 {
		t.Fatalf("observer saw %d clears, want 1", len(h.observer.cleared))
	}
	if got := h.activeGauges(t); len(got) != 0 {
		t.Errorf("the series survived resolution as %v.\n\nA resolved issue left at 0 keeps "+
			"answering instant queries forever, so the issue list only ever grows", got)
	}
	if got := h.engine.Active(); len(got) != 0 {
		t.Errorf("Active() still reports %v", got)
	}
}

func TestAFlappingConditionRestartsItsHoldTime(t *testing.T) {
	h := newHarness(t, saturationRule())

	h.serve(saturated(97, "cpu", "checkout-a"))
	h.evaluate(t)

	h.advance(50 * time.Second)
	h.serve(saturated(10, "cpu", "checkout-a"))
	h.evaluate(t)

	h.advance(50 * time.Second)
	h.serve(saturated(97, "cpu", "checkout-a"))
	if got := h.evaluate(t); len(got) != 0 {
		t.Fatalf("activated %v; the condition was false in between, so the For has to start "+
			"over rather than counting time the workload was healthy", got)
	}
}

func TestClearingOneResourceDoesNotTakeDownAnother(t *testing.T) {
	h := newHarness(t, saturationRule())
	both := gaugeFamily(familyUtilization,
		gauge(97, workloadLabels(label("resource", "cpu"), label("pod", "checkout-a"))...),
		gauge(96, workloadLabels(label("resource", "memory"), label("pod", "checkout-a"))...),
	)
	h.serve(both)
	h.evaluate(t)
	h.advance(2 * time.Minute)
	if got := h.evaluate(t); len(got) != 2 {
		t.Fatalf("activated %d issues, want one per resource", len(got))
	}

	h.advance(time.Minute)
	h.serve(gaugeFamily(familyUtilization,
		gauge(5, workloadLabels(label("resource", "cpu"), label("pod", "checkout-a"))...),
		gauge(96, workloadLabels(label("resource", "memory"), label("pod", "checkout-a"))...),
	))
	h.evaluate(t)

	gauges := h.activeGauges(t)
	if len(gauges) != 1 {
		t.Fatalf("got %d active series after CPU recovered, want memory still firing: %v",
			len(gauges), gauges)
	}
	if gauges[0]["resource"] != "memory" {
		t.Errorf("the surviving series is %v; memory is still saturated and must still fire",
			gauges[0])
	}
}

func TestASeverityChangeReplacesTheSeriesRatherThanAddingOne(t *testing.T) {
	h := newHarness(t, saturationRule())
	h.serve(saturated(82, "cpu", "checkout-a"))
	h.evaluate(t)
	h.advance(2 * time.Minute)
	h.evaluate(t)

	if got := h.activeGauges(t); len(got) != 1 || got[0]["severity"] != string(alerting.SeverityWarning) {
		t.Fatalf("expected one warning series, got %v", got)
	}

	h.advance(time.Minute)
	h.serve(saturated(99, "cpu", "checkout-a"))
	h.evaluate(t)

	gauges := h.activeGauges(t)
	if len(gauges) != 1 {
		t.Fatalf("got %d series after the severity rose, want 1; the subject would report "+
			"as firing at two severities at once: %v", len(gauges), gauges)
	}
	if gauges[0]["severity"] != string(alerting.SeverityFatal) {
		t.Errorf("severity = %q, want fatal at 99%%", gauges[0]["severity"])
	}
}

func TestTheBudgetBoundsTrackedIssues(t *testing.T) {
	h := &harness{
		gatherer: &fixedGatherer{},
		registry: prometheus.NewRegistry(),
		observer: &recorder{},
		clock:    time.Now(),
	}
	engine, err := New(Options{
		Gatherer:   h.gatherer,
		Registerer: h.registry,
		Rules:      []Rule{saturationRule()},
		Thresholds: DefaultThresholds(),
		Budget:     2,
		Now:        func() time.Time { return h.clock },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.engine = engine

	var metrics []*dto.Metric
	for _, pod := range []string{"a", "b", "c", "d", "e"} {
		metrics = append(metrics, gauge(97,
			workloadLabels(label("resource", "cpu"), label("pod", pod))...))
	}
	h.serve(gaugeFamily(familyUtilization, metrics...))
	h.evaluate(t)

	if got := h.counterValue(t, "podtrace_inspections_dropped_total", nil); got != 3 {
		t.Errorf("dropped = %v, want 3 of 5 refused at a budget of 2; an unbounded issue "+
			"map is a memory leak inside the agent", got)
	}
	h.advance(2 * time.Minute)
	if got := len(h.evaluate(t)); got != 2 {
		t.Errorf("activated %d, want the 2 that fit the budget", got)
	}
}

func TestAnIssueWithoutAPodIsReportedAsUntriggerable(t *testing.T) {
	h := newHarness(t, errorRateRule())
	h.serve(counterFamily(familyL7Requests,
		counter(0, workloadLabels(label("outcome", "ok"), label("protocol", "http"))...),
		counter(0, workloadLabels(label("outcome", "error"), label("protocol", "http"))...),
	))
	h.evaluate(t)

	h.advance(time.Minute)
	h.serve(counterFamily(familyL7Requests,
		counter(50, workloadLabels(label("outcome", "ok"), label("protocol", "http"))...),
		counter(50, workloadLabels(label("outcome", "error"), label("protocol", "http"))...),
	))
	h.evaluate(t)
	h.advance(3 * time.Minute)
	h.serve(counterFamily(familyL7Requests,
		counter(100, workloadLabels(label("outcome", "ok"), label("protocol", "http"))...),
		counter(100, workloadLabels(label("outcome", "error"), label("protocol", "http"))...),
	))
	activated := h.evaluate(t)

	if len(activated) != 1 {
		t.Fatalf("activated %d, want the error-rate issue: %v", len(activated), activated)
	}
	if activated[0].Subject.Pod != "" {
		t.Fatal("fixture unexpectedly carried a pod")
	}
	if got := h.counterValue(t, "podtrace_inspections_untriggerable_total", nil); got != 1 {
		t.Errorf("untriggerable = %v, want 1; an issue that cannot start a session must say so", got)
	}
}

func TestAFailedGatherIsReportedRatherThanReadAsHealthy(t *testing.T) {
	h := newHarness(t, saturationRule())
	h.gatherer.err = errors.New("collector exploded")

	if _, err := h.engine.Evaluate(); err == nil {
		t.Fatal("a total gather failure reported success; every rule would read as healthy " +
			"while the inspections were actually blind")
	}
	if got := h.counterValue(t, "podtrace_inspections_failures_total", nil); got != 1 {
		t.Errorf("failures = %v, want 1", got)
	}
	if got := h.counterValue(t, "podtrace_inspections_evaluations_total", nil); got != 0 {
		t.Errorf("evaluations = %v, want 0; a failed pass is not an evaluation", got)
	}
}

func TestAPartialGatherStillEvaluatesButIsCounted(t *testing.T) {
	h := newHarness(t, saturationRule())
	h.gatherer.err = errors.New("one collector failed")
	h.serve(saturated(97, "cpu", "checkout-a"))

	if _, err := h.engine.Evaluate(); err == nil {
		t.Error("a partial gather hid its error")
	}
	h.advance(2 * time.Minute)
	if _, err := h.engine.Evaluate(); err == nil {
		t.Error("a partial gather hid its error")
	}
	if got := h.engine.Active(); len(got) != 1 {
		t.Errorf("the rule did not evaluate over the samples that did arrive: %v", got)
	}
	if got := h.counterValue(t, "podtrace_inspections_failures_total", nil); got != 2 {
		t.Errorf("failures = %v, want 2", got)
	}
}

func TestTransitionsAreCounted(t *testing.T) {
	h := newHarness(t, saturationRule())
	h.serve(saturated(97, "cpu", "checkout-a"))
	h.evaluate(t)
	h.advance(2 * time.Minute)
	h.evaluate(t)
	h.advance(time.Minute)
	h.serve(saturated(3, "cpu", "checkout-a"))
	h.evaluate(t)

	for transition, want := range map[string]float64{"activated": 1, "cleared": 1} {
		got := h.counterValue(t, "podtrace_inspections_transitions_total", map[string]string{
			"id": string(detector.IDResourceSaturation), "transition": transition,
		})
		if got != want {
			t.Errorf("%s transitions = %v, want %v; a flat counter means the loop is not "+
				"actually reaching a verdict", transition, got, want)
		}
	}
}

func TestNewFillsInTheShippedDefaults(t *testing.T) {

	e, err := New(Options{Gatherer: &fixedGatherer{}})
	if err != nil {
		t.Fatalf("New with minimal options: %v", err)
	}
	if e.now == nil {
		t.Error("no clock was installed")
	}
	if len(e.rules) == 0 {
		t.Error("no rules were installed; every evaluation would find nothing")
	}
	if e.limits.unset() {
		t.Error("thresholds left zero; an error-rate threshold of 0% fires on all traffic")
	}
	if e.budget <= 0 {
		t.Error("budget left unbounded")
	}
}

func TestRegisteringTwiceIsReportedRatherThanPanicking(t *testing.T) {

	reg := prometheus.NewRegistry()
	if _, err := New(Options{Gatherer: &fixedGatherer{}, Registerer: reg}); err != nil {
		t.Fatalf("first New: %v", err)
	}
	if _, err := New(Options{Gatherer: &fixedGatherer{}, Registerer: reg}); err == nil {
		t.Error("a duplicate registration reported success; the collision would fail " +
			"every scrape at runtime instead")
	}
}

func TestActiveIsOrderedForStableOutput(t *testing.T) {
	h := newHarness(t, saturationRule())
	h.serve(gaugeFamily(familyUtilization,
		gauge(97, workloadLabels(label("resource", "memory"), label("pod", "a"))...),
		gauge(96, workloadLabels(label("resource", "cpu"), label("pod", "a"))...),
	))
	h.evaluate(t)
	h.advance(2 * time.Minute)
	h.evaluate(t)

	first := h.engine.Active()
	if len(first) != 2 {
		t.Fatalf("Active() = %d issues, want 2", len(first))
	}
	for i := 0; i < 5; i++ {
		again := h.engine.Active()
		for j := range again {
			if again[j].Key() != first[j].Key() {
				t.Fatalf("Active() order changed between calls: %q then %q",
					first[j].Key(), again[j].Key())
			}
		}
	}
	if first[0].Key() > first[1].Key() {
		t.Errorf("Active() is not sorted: %q before %q", first[0].Key(), first[1].Key())
	}
}

func TestATotalGatherFailureDoesNotAdvanceThePreviousSnapshot(t *testing.T) {

	h := newHarness(t, errorRateRule())
	h.serve(counterFamily(familyL7Requests,
		counter(10, workloadLabels(label("outcome", "ok"))...)))
	h.evaluate(t)

	h.gatherer.err = errors.New("collector exploded")
	h.gatherer.families = nil
	if _, err := h.engine.Evaluate(); err == nil {
		t.Fatal("a total gather failure reported success")
	}
	if h.engine.previous.IsZero() {
		t.Error("the last good snapshot was discarded on a failed gather")
	}
}

func TestSeverityRankOrdersTheWholeVocabulary(t *testing.T) {

	ranks := map[alerting.AlertSeverity]int{
		alerting.SeverityFatal:    severityRank(alerting.SeverityFatal),
		alerting.SeverityCritical: severityRank(alerting.SeverityCritical),
		alerting.SeverityError:    severityRank(alerting.SeverityError),
		alerting.SeverityWarning:  severityRank(alerting.SeverityWarning),
	}
	if ranks[alerting.SeverityFatal] <= ranks[alerting.SeverityCritical] ||
		ranks[alerting.SeverityCritical] <= ranks[alerting.SeverityError] ||
		ranks[alerting.SeverityError] <= ranks[alerting.SeverityWarning] {
		t.Errorf("severities do not order fatal > critical > error > warning: %v", ranks)
	}
	if got := severityRank(alerting.AlertSeverity("not-a-severity")); got != 0 {
		t.Errorf("an unknown severity ranked %d, want 0 so it cannot outrank a real one", got)
	}
}

func TestTheHigherSeverityWinsWhenOneSubjectFiresTwice(t *testing.T) {

	warn := detector.Issue{
		ID: detector.IDResourceSaturation, Severity: alerting.SeverityWarning,
		Subject: detector.Subject{Namespace: "shop", Workload: "web", Resource: "cpu"},
		Message: "warn",
	}
	crit := warn
	crit.Severity = alerting.SeverityCritical
	crit.Message = "crit"

	both := Rule{
		ID: detector.IDResourceSaturation, For: 0, Query: "x",
		Eval: func(Window, Thresholds) []detector.Issue {
			return []detector.Issue{warn, crit, warn}
		},
	}
	h := newHarness(t, both)
	h.serve()
	activated := h.evaluate(t)
	if len(activated) != 1 {
		t.Fatalf("activated %d, want 1 deduplicated issue", len(activated))
	}
	if activated[0].Severity != alerting.SeverityCritical {
		t.Errorf("severity = %q, want critical to win over warning", activated[0].Severity)
	}
}

func TestAShortenedHoldTimeActuallyShortensTheWait(t *testing.T) {
	h := &harness{
		gatherer: &fixedGatherer{},
		registry: prometheus.NewRegistry(),
		observer: &recorder{},
		clock:    time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC),
	}
	th := DefaultThresholds()
	th.HoldTime = 20 * time.Second
	engine, err := New(Options{
		Gatherer:   h.gatherer,
		Registerer: h.registry,
		Rules:      []Rule{errorRateRule()},
		Thresholds: th,
		Observer:   h.observer,
		Now:        func() time.Time { return h.clock },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.engine = engine

	h.serve(counterFamily(familyL7Requests,
		counter(0, workloadLabels(label("outcome", "error"))...)))
	h.evaluate(t)

	h.advance(time.Minute)
	h.serve(counterFamily(familyL7Requests,
		counter(600, workloadLabels(label("outcome", "error"))...)))
	h.evaluate(t)

	h.advance(25 * time.Second)
	h.serve(counterFamily(familyL7Requests,
		counter(1200, workloadLabels(label("outcome", "error"))...)))
	activated := h.evaluate(t)

	if len(activated) != 1 {
		t.Fatalf("activated %d issues 25s after the condition began, want 1 under a 20s "+
			"hold; the rule's own default is 2m and would still be waiting", len(activated))
	}
}
