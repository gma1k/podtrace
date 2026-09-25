package inspect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/gma1k/podtrace/internal/diagnose/detector"
)

func evalOnce(t *testing.T, rule Rule, prev, cur []*dto.MetricFamily, interval time.Duration) []detector.Issue {
	t.Helper()
	start := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	before, err := Take(&fixedGatherer{families: prev}, start)
	if err != nil {
		t.Fatalf("Take(prev): %v", err)
	}
	after, err := Take(&fixedGatherer{families: cur}, start.Add(interval))
	if err != nil {
		t.Fatalf("Take(cur): %v", err)
	}
	return rule.Eval(Window{Prev: before, Cur: after}, DefaultThresholds())
}

func TestEveryRuleIsRegisteredAndDocumented(t *testing.T) {
	registered := map[detector.ID]bool{}
	for _, id := range detector.Registry {
		registered[id] = true
	}

	seen := map[detector.ID]bool{}
	for _, rule := range Rules() {
		if !registered[rule.ID] {
			t.Errorf("rule %q is not in the issue registry; its id would appear in "+
				"podtrace_issue_active without being part of the documented vocabulary", rule.ID)
		}
		if seen[rule.ID] {
			t.Errorf("two rules share the id %q; their issues would collide on the same "+
				"series and clear each other", rule.ID)
		}
		seen[rule.ID] = true

		if rule.For <= 0 {
			t.Errorf("rule %q has no hold time; a single interval's blip would page someone",
				rule.ID)
		}
		if rule.Query == "" {
			t.Errorf("rule %q carries no query; an operator cannot reproduce what it saw", rule.ID)
		}
		if rule.Eval == nil {
			t.Fatalf("rule %q has no Eval", rule.ID)
		}
	}

	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "continuous-inspections.md"))
	if err != nil {
		t.Fatalf("read docs/continuous-inspections.md: %v", err)
	}
	for _, rule := range Rules() {
		if !strings.Contains(string(doc), string(rule.ID)) {
			t.Errorf("rule %q is not mentioned in docs/continuous-inspections.md.\n\nIssue "+
				"ids are contractual and show up in podtrace_issue_active and in alert "+
				"routing, so a rule that can page someone has to be findable by the id they "+
				"are paged with.", rule.ID)
		}
	}
}

func TestEveryRuleReadsAFamilyTheSurfaceActuallyExports(t *testing.T) {
	surface := map[string]bool{
		familyL7Requests:      true,
		familyL7Duration:      true,
		familyUtilization:     true,
		familyAcquire:         true,
		familyConnections:     true,
		familyNetworkLatency:  true,
		familyPoolUtilization: true,
		familyCPURunqueue:     true,
		familyLockContention:  true,
		familyNetworkRTT:      true,
	}
	for family := range surface {
		if !strings.HasPrefix(family, "podtrace_workload_") {
			t.Errorf("family %q is not on the workload surface", family)
		}
	}
}

func TestNoRuleFiresOnTheFirstEvaluation(t *testing.T) {
	start := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	snapshot, err := Take(&fixedGatherer{families: []*dto.MetricFamily{
		counterFamily(familyL7Requests,
			counter(1000, workloadLabels(label("outcome", "error"))...)),
		histogramFamily(familyL7Duration,
			histogram(1000, 9000, workloadLabels(label("protocol", "http"))...)),
	}}, start)
	if err != nil {
		t.Fatalf("Take: %v", err)
	}

	window := Window{Cur: snapshot}
	if window.Ready() {
		t.Fatal("a window with no previous snapshot reported ready")
	}
	for _, rule := range Rules() {
		if rule.ID == detector.IDResourceSaturation {
			continue
		}
		if got := rule.Eval(window, DefaultThresholds()); len(got) != 0 {
			t.Errorf("rule %q fired on the first evaluation: %v", rule.ID, got)
		}
	}
}

func TestErrorRateFiresOnTheWorkloadRatioNotPerProtocol(t *testing.T) {
	prev := []*dto.MetricFamily{(counterFamily(familyL7Requests,
		counter(0, workloadLabels(label("outcome", "ok"), label("protocol", "http"))...),
		counter(0, workloadLabels(label("outcome", "error"), label("protocol", "grpc"))...),
	))}
	cur := []*dto.MetricFamily{(counterFamily(familyL7Requests,
		counter(1000, workloadLabels(label("outcome", "ok"), label("protocol", "http"))...),
		counter(1, workloadLabels(label("outcome", "error"), label("protocol", "grpc"))...),
	))}

	if got := evalOnce(t, errorRateRule(), prev, cur, time.Minute); len(got) != 0 {
		t.Errorf("fired at 1 error in 1001 requests: %v.\n\nDividing grpc errors by grpc "+
			"requests would read 100%%, which is true and useless", got)
	}

	cur = []*dto.MetricFamily{(counterFamily(familyL7Requests,
		counter(900, workloadLabels(label("outcome", "ok"), label("protocol", "http"))...),
		counter(100, workloadLabels(label("outcome", "error"), label("protocol", "http"))...),
	))}
	got := evalOnce(t, errorRateRule(), prev, cur, time.Minute)
	if len(got) != 1 {
		t.Fatalf("got %d issues at a 10%% error rate, want 1", len(got))
	}
	if got[0].ID != detector.IDL7ErrorRate {
		t.Errorf("id = %q", got[0].ID)
	}
	if !strings.Contains(got[0].Message, "10.0%") {
		t.Errorf("message %q does not state the measured rate", got[0].Message)
	}
}

func TestErrorRateStaysQuietOnIdleTraffic(t *testing.T) {
	prev := []*dto.MetricFamily{(counterFamily(familyL7Requests,
		counter(0, workloadLabels(label("outcome", "error"), label("protocol", "http"))...)))}
	cur := []*dto.MetricFamily{(counterFamily(familyL7Requests,
		counter(1, workloadLabels(label("outcome", "error"), label("protocol", "http"))...)))}

	if got := evalOnce(t, errorRateRule(), prev, cur, 10*time.Minute); len(got) != 0 {
		t.Errorf("fired on 1 request in 10 minutes: %v; every idle workload with one "+
			"failure would page someone", got)
	}
}

func TestACounterResetIsNotReadAsAHugeRate(t *testing.T) {
	prev := []*dto.MetricFamily{(counterFamily(familyL7Requests,
		counter(5000, workloadLabels(label("outcome", "error"))...)))}
	cur := []*dto.MetricFamily{(counterFamily(familyL7Requests,
		counter(3, workloadLabels(label("outcome", "error"))...)))}

	start := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	before, _ := Take(&fixedGatherer{families: prev}, start)
	after, _ := Take(&fixedGatherer{families: cur}, start.Add(time.Minute))
	deltas := Window{Prev: before, Cur: after}.Deltas(familyL7Requests)
	if len(deltas) != 1 {
		t.Fatalf("got %d deltas", len(deltas))
	}
	if !deltas[0].Reset {
		t.Error("a counter that went backwards was not flagged as a reset")
	}
	if got := deltas[0].PerSecond(time.Minute); got != 0 {
		t.Errorf("rate across a reset = %v, want 0", got)
	}
}

func TestANewSeriesCountsItsWholeValue(t *testing.T) {
	cur := []*dto.MetricFamily{counterFamily(familyL7Requests,
		counter(600, workloadLabels(label("outcome", "error"), label("protocol", "http"))...))}

	got := evalOnce(t, errorRateRule(), []*dto.MetricFamily{
		counterFamily(familyL7Requests),
	}, cur, time.Minute)
	if len(got) != 1 {
		t.Fatalf("a newly admitted series produced %d issues, want 1", len(got))
	}
	if got[0].Subject.Workload != "checkout" {
		t.Errorf("workload = %q, want checkout", got[0].Subject.Workload)
	}
}

func TestLatencyUsesTheIntervalMeanNotTheLifetimeMean(t *testing.T) {
	prev := []*dto.MetricFamily{(histogramFamily(familyL7Duration,
		histogram(100_000, 1_000, workloadLabels(label("protocol", "http"))...)))}
	cur := []*dto.MetricFamily{(histogramFamily(familyL7Duration,
		histogram(100_010, 1_040, workloadLabels(label("protocol", "http"))...)))}

	got := evalOnce(t, latencyRule(), prev, cur, time.Minute)
	if len(got) != 1 {
		t.Fatalf("got %d issues; 10 requests taking 4s each must fire even though the "+
			"lifetime mean is 10ms", len(got))
	}
	if !strings.Contains(got[0].Message, "4000ms") {
		t.Errorf("message %q does not report the interval mean", got[0].Message)
	}
}

func TestSaturationBandsMatchTheDiagnosticDetector(t *testing.T) {
	for _, tc := range []struct {
		pct   float64
		fires bool
	}{{10, false}, {82, true}, {91, true}, {99, true}} {
		cur := []*dto.MetricFamily{(saturated(tc.pct, "cpu", "checkout-a"))}
		got := evalOnce(t, saturationRule(), nil, cur, time.Minute)
		if (len(got) > 0) != tc.fires {
			t.Errorf("%.0f%% produced %d issues, want fires=%v", tc.pct, len(got), tc.fires)
			continue
		}
		if !tc.fires {
			continue
		}
		want, _ := detector.SeverityForUtilization(int(tc.pct), 80, 90, 95)
		if got[0].Severity != want {
			t.Errorf("%.0f%% fired at %q, the detector bands it as %q",
				tc.pct, got[0].Severity, want)
		}
	}
}

func TestEveryIssueARuleProducesIsComplete(t *testing.T) {
	cases := []struct {
		rule Rule
		prev []*dto.MetricFamily
		cur  []*dto.MetricFamily
	}{
		{
			rule: saturationRule(),
			cur:  []*dto.MetricFamily{(saturated(97, "cpu", "checkout-a"))},
		},
		{
			rule: errorRateRule(),
			prev: []*dto.MetricFamily{(counterFamily(familyL7Requests,
				counter(0, workloadLabels(label("outcome", "error"), label("protocol", "http"))...)))},
			cur: []*dto.MetricFamily{(counterFamily(familyL7Requests,
				counter(500, workloadLabels(label("outcome", "error"), label("protocol", "http"))...)))},
		},
		{
			rule: latencyRule(),
			prev: []*dto.MetricFamily{(histogramFamily(familyL7Duration,
				histogram(0, 0, workloadLabels(label("protocol", "http"))...)))},
			cur: []*dto.MetricFamily{(histogramFamily(familyL7Duration,
				histogram(10, 50, workloadLabels(label("protocol", "http"))...)))},
		},
	}

	for _, tc := range cases {
		issues := evalOnce(t, tc.rule, tc.prev, tc.cur, time.Minute)
		if len(issues) == 0 {
			t.Errorf("rule %q produced nothing from a fixture built to trip it", tc.rule.ID)
			continue
		}
		for _, issue := range issues {
			if issue.ID != tc.rule.ID {
				t.Errorf("rule %q emitted id %q", tc.rule.ID, issue.ID)
			}
			if issue.Severity == "" {
				t.Errorf("%q has no severity; the trigger machinery ranks it as unknown", issue.ID)
			}
			if issue.Message == "" {
				t.Errorf("%q has no message", issue.ID)
			}
			if issue.Remediation == "" {
				t.Errorf("%q has no remediation; an issue that cannot say what to do next "+
					"is a notification, not a diagnosis", issue.ID)
			}
			if len(issue.Evidence) == 0 {
				t.Errorf("%q carries no evidence; a consumer would have to re-derive why "+
					"it fired", issue.ID)
			}
			if issue.Subject.Namespace == "" || issue.Subject.Workload == "" {
				t.Errorf("%q has no subject identity: %+v", issue.ID, issue.Subject)
			}
		}
	}
}

func TestEveryRateRuleSkipsSeriesAcrossACounterReset(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule Rule
		prev []*dto.MetricFamily
		cur  []*dto.MetricFamily
	}{
		{
			name: "error rate",
			rule: errorRateRule(),
			prev: []*dto.MetricFamily{counterFamily(familyL7Requests,
				counter(50_000, workloadLabels(label("outcome", "error"))...))},
			cur: []*dto.MetricFamily{counterFamily(familyL7Requests,
				counter(9, workloadLabels(label("outcome", "error"))...))},
		},
		{
			name: "latency",
			rule: latencyRule(),
			prev: []*dto.MetricFamily{histogramFamily(familyL7Duration,
				histogram(50_000, 90_000, workloadLabels(label("protocol", "http"))...))},
			cur: []*dto.MetricFamily{histogramFamily(familyL7Duration,
				histogram(3, 90, workloadLabels(label("protocol", "http"))...))},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := evalOnce(t, tc.rule, tc.prev, tc.cur, time.Minute); len(got) != 0 {
				t.Errorf("rule %q fired across a counter reset: %v.\n\nThe two totals span "+
					"different process lifetimes, so any rate computed from them is fiction.",
					tc.rule.ID, got)
			}
		})
	}
}

func TestLatencySkipsSeriesWithNoNewObservations(t *testing.T) {

	same := histogramFamily(familyL7Duration,
		histogram(500, 4_000, workloadLabels(label("protocol", "http"))...))
	if got := evalOnce(t, latencyRule(),
		[]*dto.MetricFamily{same}, []*dto.MetricFamily{same}, time.Minute); len(got) != 0 {
		t.Errorf("latency fired on a series with no new observations: %v", got)
	}
}

func TestErrorRateSkipsAWorkloadWithNoRequestsInTheInterval(t *testing.T) {
	same := counterFamily(familyL7Requests,
		counter(1_000, workloadLabels(label("outcome", "ok"))...))
	if got := evalOnce(t, errorRateRule(),
		[]*dto.MetricFamily{same}, []*dto.MetricFamily{same}, time.Minute); len(got) != 0 {
		t.Errorf("error rate fired on an idle workload: %v", got)
	}
}

func TestSaturationIgnoresAReadingBelowEveryBand(t *testing.T) {
	cur := []*dto.MetricFamily{saturated(12, "cpu", "pod-a")}
	if got := evalOnce(t, saturationRule(), nil, cur, time.Minute); len(got) != 0 {
		t.Errorf("saturation fired at 12%%: %v", got)
	}
}

func TestLatencyIgnoresAWorkloadUnderItsThreshold(t *testing.T) {

	prev := []*dto.MetricFamily{histogramFamily(familyL7Duration,
		histogram(0, 0, workloadLabels(label("protocol", "http"))...))}
	cur := []*dto.MetricFamily{histogramFamily(familyL7Duration,
		histogram(200, 2, workloadLabels(label("protocol", "http"))...))}

	if got := evalOnce(t, latencyRule(), prev, cur, time.Minute); len(got) != 0 {
		t.Errorf("latency fired at a 10ms mean against a 1s threshold: %v", got)
	}
}

func TestRuleFamiliesCoversEveryFamilyTheRulesRead(t *testing.T) {
	declared := map[string]bool{}
	for _, f := range RuleFamilies() {
		declared[f] = true
	}

	read := map[string]bool{}
	for _, family := range []string{
		familyL7Requests, familyL7Duration, familyUtilization, familyAcquire,
		familyConnections, familyNetworkLatency, familyPoolUtilization,
		familyCPURunqueue, familyLockContention, familyNetworkRTT,
	} {
		read[family] = true
	}

	for family := range read {
		if !declared[family] {
			t.Errorf("the rules read %q but RuleFamilies() omits it.\n\nA FamilySource is "+
				"asked for exactly that set, so the rule would see no samples and report "+
				"the workload healthy forever, with nothing failing to say so.", family)
		}
	}
	for family := range declared {
		if !read[family] {
			t.Errorf("RuleFamilies() declares %q but no rule reads it; collecting it every "+
				"interval is work for nothing", family)
		}
	}
}

func TestEveryDeclaredRuleFamilyUsesTheWorkloadPrefix(t *testing.T) {
	for _, family := range RuleFamilies() {
		if !strings.HasPrefix(family, "podtrace_workload_") {
			t.Errorf("family %q is not on the workload surface, so no FamilySource on this "+
				"plane can serve it", family)
		}
	}
}

func TestHoldTimeFallsBackToEachRulesOwnDefault(t *testing.T) {
	defaults := DefaultThresholds()
	for _, rule := range Rules() {
		if got := defaults.holdTimeFor(rule); got != rule.For {
			t.Errorf("rule %q holds for %v with no override, want its own %v",
				rule.ID, got, rule.For)
		}
	}
}

func TestAGlobalHoldTimeReplacesEveryRulesDefault(t *testing.T) {
	th := DefaultThresholds()
	th.HoldTime = 7 * time.Second
	for _, rule := range Rules() {
		if got := th.holdTimeFor(rule); got != 7*time.Second {
			t.Errorf("rule %q holds for %v, want the global override 7s", rule.ID, got)
		}
	}
}

func TestAPerRuleHoldTimeBeatsTheGlobalOne(t *testing.T) {
	th := DefaultThresholds()
	th.HoldTime = 7 * time.Second
	th.HoldTimes = map[detector.ID]time.Duration{
		detector.IDResourceSaturation: 90 * time.Second,
	}
	for _, rule := range Rules() {
		want := 7 * time.Second
		if rule.ID == detector.IDResourceSaturation {
			want = 90 * time.Second
		}
		if got := th.holdTimeFor(rule); got != want {
			t.Errorf("rule %q holds for %v, want %v", rule.ID, got, want)
		}
	}
}

func TestANonPositiveHoldTimeOverrideIsIgnored(t *testing.T) {
	th := DefaultThresholds()
	th.HoldTime = 0
	th.HoldTimes = map[detector.ID]time.Duration{
		detector.IDL7ErrorRate:        0,
		detector.IDResourceSaturation: -time.Minute,
	}
	for _, rule := range Rules() {
		if got := th.holdTimeFor(rule); got != rule.For {
			t.Errorf("rule %q holds for %v after a non-positive override, want its own %v; "+
				"a zero hold would fire on a single interval's blip", rule.ID, got, rule.For)
		}
	}
}

func TestUnsetDistinguishesAnEmptyThresholdsFromAConfiguredOne(t *testing.T) {
	if !(Thresholds{}).unset() {
		t.Error("an empty Thresholds did not report unset, so New would not fill in defaults")
	}
	if DefaultThresholds().unset() {
		t.Error("the shipped defaults reported unset")
	}
	for name, th := range map[string]Thresholds{
		"error rate": {ErrorRatePercent: 1},
		"min rate":   {MinRequestsPerSecond: 1},
		"latency":    {MeanLatency: time.Second},
		"warn band":  {UtilizationWarn: 1},
		"crit band":  {UtilizationCritical: 1},
		"emerg band": {UtilizationEmergency: 1},
		"hold time":  {HoldTime: time.Second},
		"hold times": {HoldTimes: map[detector.ID]time.Duration{detector.IDL7ErrorRate: time.Second}},
	} {
		if th.unset() {
			t.Errorf("Thresholds with only %s set reported unset; New would overwrite it "+
				"with the shipped defaults", name)
		}
	}
}
