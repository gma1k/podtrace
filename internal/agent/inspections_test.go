package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"sync"

	"github.com/gma1k/podtrace/internal/alerting"
	"github.com/gma1k/podtrace/internal/config"
	"github.com/gma1k/podtrace/internal/diagnose/detector"
	"github.com/gma1k/podtrace/internal/inspect"
	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func saturationIssue(pod string) detector.Issue {
	return detector.Issue{
		ID:       detector.IDResourceSaturation,
		Severity: alerting.SeverityCritical,
		Subject: detector.Subject{
			Namespace: "shop",
			Workload:  "checkout",
			Container: "app",
			Pod:       pod,
			Resource:  "cpu",
		},
		Evidence:    []detector.Evidence{detector.NewEvidence("utilization", 93, 80, "%")},
		Remediation: "Raise the limit.",
		Message:     "Resource limit CRITICAL: shop/checkout cpu at 93% utilization",
	}
}

type fakeEventSink struct {
	sent []*alerting.Alert
	err  error
}

func (f *fakeEventSink) Send(_ context.Context, alert *alerting.Alert) error {
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, alert)
	return nil
}

func newTestAlerter() (*issueAlerter, *[]*alerting.Alert) {
	sink := &fakeEventSink{}
	a := &issueAlerter{
		events: sink,
		now:    func() time.Time { return time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC) },
		logger: logr.Discard(),
	}
	return a, &sink.sent
}

func TestIssueAlertsDoNotDependOnTheProcessAlertManagerBeingEnabled(t *testing.T) {
	sink := &fakeEventSink{}
	alerter := &issueAlerter{
		events:  sink,
		manager: nil,
		now:     func() time.Time { return time.Now() },
		logger:  logr.Discard(),
	}
	alerter.IssueActivated(saturationIssue("checkout-abc"))

	if len(sink.sent) != 1 {
		t.Fatalf("wrote %d Events with no alert manager, want 1.\n\nThe trigger Event is "+
			"what makes inspections.alerts mean anything; gating it behind an unrelated "+
			"alerting toggle makes the whole metric-to-session loop silently inert.",
			len(sink.sent))
	}
	if sink.sent[0].Source != alerting.AlertSourceIssue {
		t.Errorf("source = %q, want %q", sink.sent[0].Source, alerting.AlertSourceIssue)
	}
}

func TestAFailedEventWriteIsCountedNotSwallowed(t *testing.T) {
	metrics := NewMetrics()
	alerter := &issueAlerter{
		events:      &fakeEventSink{err: errors.New("apiserver refused")},
		now:         time.Now,
		logger:      logr.Discard(),
		undelivered: metrics.IssueAlertUndelivered,
	}
	alerter.IssueActivated(saturationIssue("checkout-abc"))

	if got := plainCounterValue(t, metrics.IssueAlertUndelivered); got != 1 {
		t.Errorf("undelivered = %v, want 1; an Event write that fails leaves the issue "+
			"graphed but unable to start a session, which must not be silent", got)
	}
}

func TestNoEventWriterAtAllIsCounted(t *testing.T) {
	metrics := NewMetrics()
	alerter := &issueAlerter{
		events:      nil,
		now:         time.Now,
		logger:      logr.Discard(),
		undelivered: metrics.IssueAlertUndelivered,
	}
	alerter.IssueActivated(saturationIssue("checkout-abc"))

	if got := plainCounterValue(t, metrics.IssueAlertUndelivered); got != 1 {
		t.Errorf("undelivered = %v, want 1", got)
	}
}

func TestAnActivatedIssueRaisesTheAlertThatStartsASession(t *testing.T) {
	alerter, sent := newTestAlerter()
	alerter.IssueActivated(saturationIssue("checkout-abc"))

	if len(*sent) != 1 {
		t.Fatalf("sent %d alerts, want 1; without one the issue only draws a line on a "+
			"dashboard and the operator still has to author the session by hand", len(*sent))
	}
	alert := (*sent)[0]

	if alert.Source != alerting.AlertSourceIssue {
		t.Errorf("source = %q, want %q; the operator matches a PodTraceSchedule trigger on "+
			"this token and ignores anything else", alert.Source, alerting.AlertSourceIssue)
	}
	if alert.PodName != "checkout-abc" || alert.Namespace != "shop" {
		t.Errorf("alert targets %s/%s, want shop/checkout-abc", alert.Namespace, alert.PodName)
	}
	if alert.Severity != alerting.SeverityCritical {
		t.Errorf("severity = %q, want the issue's own", alert.Severity)
	}
	if alert.ErrorCode != string(detector.IDResourceSaturation) {
		t.Errorf("error code = %q, want the stable issue id so a consumer can route on it",
			alert.ErrorCode)
	}
}

func TestTheAlertIsBuildableIntoTheTriggerEvent(t *testing.T) {
	alerter, sent := newTestAlerter()
	alerter.IssueActivated(saturationIssue("checkout-abc"))

	event := alerting.BuildAlertEvent((*sent)[0], time.Now())
	if event == nil {
		t.Fatal("BuildAlertEvent refused the alert; the Kubernetes Event would never be written")
	}
	if event.InvolvedObject.Kind != "Pod" {
		t.Errorf("involved object is %q; the operator ignores an Event that names anything "+
			"but a Pod", event.InvolvedObject.Kind)
	}
	if got := event.Annotations["podtrace.io/alert-source"]; got != alerting.AlertSourceIssue {
		t.Errorf("alert-source annotation = %q, want issue", got)
	}
}

func TestAWorkloadIssueBorrowsAPodFromThisNode(t *testing.T) {
	alerter, sent := newTestAlerter()
	alerter.resolvePod = func(namespace, workload string) string {
		if namespace == "shop" && workload == "checkout" {
			return "checkout-resolved"
		}
		return ""
	}

	issue := saturationIssue("")
	issue.ID = detector.IDL7ErrorRate
	issue.Subject.Resource = ""
	alerter.IssueActivated(issue)

	if len(*sent) != 1 {
		t.Fatalf("sent %d alerts, want 1", len(*sent))
	}
	if got := (*sent)[0].PodName; got != "checkout-resolved" {
		t.Errorf("pod = %q, want the resolved one", got)
	}
}

func TestAnUnresolvableIssueIsCountedNotDropped(t *testing.T) {
	metrics := NewMetrics()
	alerter, sent := newTestAlerter()
	alerter.resolvePod = func(string, string) string { return "" }
	alerter.unresolvedPods = metrics.IssuePodUnresolved

	issue := saturationIssue("")
	issue.ID = detector.IDL7ErrorRate
	alerter.IssueActivated(issue)

	if len(*sent) != 0 {
		t.Errorf("an alert with no pod was sent as %+v; BuildAlertEvent returns nil for it, "+
			"so it would vanish with nothing recorded", (*sent)[0])
	}
	if got := plainCounterValue(t, metrics.IssuePodUnresolved); got != 1 {
		t.Errorf("unresolved counter = %v, want 1; a silently open metric-to-session loop "+
			"is exactly the failure this counter exists to expose", got)
	}
}

func TestIssueTextIsSanitizedBeforeItReachesAnEvent(t *testing.T) {
	alerter, sent := newTestAlerter()
	issue := saturationIssue("checkout-abc")
	issue.Message = "Resource limit CRITICAL: shop/\x1b[2Jevil at 93%"
	issue.Remediation = "Do \x1b]0;pwned\x07 this"
	alerter.IssueActivated(issue)

	alert := (*sent)[0]
	if strings.ContainsRune(alert.Title, 0x1b) {
		t.Errorf("the title carries an escape sequence: %q", alert.Title)
	}
	if strings.ContainsRune(alert.Message, 0x1b) {
		t.Errorf("the message carries an escape sequence: %q", alert.Message)
	}
	for _, rec := range alert.Recommendations {
		if strings.ContainsRune(rec, 0x1b) {
			t.Errorf("a recommendation carries an escape sequence: %q", rec)
		}
	}
}

func TestTheEvidenceTravelsOnTheAlert(t *testing.T) {
	alerter, sent := newTestAlerter()
	alerter.IssueActivated(saturationIssue("checkout-abc"))

	context := (*sent)[0].Context
	if got := context["utilization"]; got != float64(93) {
		t.Errorf("context[utilization] = %v, want 93; without the measured value a consumer "+
			"has to re-run the query to learn why it fired", got)
	}
	if got := context["utilization_threshold"]; got != float64(80) {
		t.Errorf("context[utilization_threshold] = %v, want 80", got)
	}
	if got := context["issue_id"]; got != string(detector.IDResourceSaturation) {
		t.Errorf("context[issue_id] = %v", got)
	}
}

func TestAClearedIssueSendsNoAlert(t *testing.T) {
	alerter, sent := newTestAlerter()
	alerter.IssueCleared(saturationIssue("checkout-abc"))
	if len(*sent) != 0 {
		t.Errorf("recovery raised an alert: %+v", (*sent)[0])
	}
}

func TestPodForPicksAStablePodOfTheWorkload(t *testing.T) {
	enricher := NewPodEnricher()
	enricher.Snapshot([]PodCgroupEntry{
		podEntryOwnedBy("shop", "checkout-c", "checkout-7d9f8b6c5d", "app", 3),
		podEntryOwnedBy("shop", "checkout-a", "checkout-7d9f8b6c5d", "app", 1),
		podEntryOwnedBy("shop", "checkout-b", "checkout-7d9f8b6c5d", "app", 2),
		podEntryOwnedBy("shop", "payments-a", "payments-7d9f8b6c5d", "app", 4),
	})

	first, ok := enricher.PodFor("shop", "checkout")
	if !ok {
		t.Fatal("no pod resolved for a workload the node is tracking")
	}
	for i := 0; i < 20; i++ {
		again, _ := enricher.PodFor("shop", "checkout")
		if again != first {
			t.Fatalf("PodFor returned %q then %q; an unstable choice makes two inspections of "+
				"one workload look like two different alerts to the deduplicator", first, again)
		}
	}
	if first != "checkout-a" {
		t.Errorf("resolved %q, want the lowest name", first)
	}

	if _, ok := enricher.PodFor("shop", "nothing-here"); ok {
		t.Error("a workload this node does not track resolved a pod")
	}
	if _, ok := enricher.PodFor("", "checkout"); ok {
		t.Error("an empty namespace resolved a pod")
	}
	var nilEnricher *PodEnricher
	if _, ok := nilEnricher.PodFor("shop", "checkout"); ok {
		t.Error("a nil enricher resolved a pod")
	}
}

func TestEnricherPodResolverHandlesANilEnricher(t *testing.T) {
	if enricherPodResolver(nil) != nil {
		t.Error("a nil enricher produced a resolver that would be called and panic")
	}
	resolve := enricherPodResolver(NewPodEnricher())
	if got := resolve("shop", "checkout"); got != "" {
		t.Errorf("an empty enricher resolved %q", got)
	}
}

func plainCounterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("write counter: %v", err)
	}
	return m.GetCounter().GetValue()
}

func TestBuildInspectionEngineIsAbsentUnlessEnabled(t *testing.T) {
	original := config.InspectionsEnabled
	config.InspectionsEnabled = false
	t.Cleanup(func() { config.InspectionsEnabled = original })

	engine, err := buildInspectionEngine(NewMetrics(), stubFamilySource{}, nil, &fakeEventSink{}, logr.Discard())
	if err != nil {
		t.Fatalf("buildInspectionEngine: %v", err)
	}
	if engine != nil {
		t.Error("an engine was built with inspections disabled; it would evaluate rules " +
			"and raise alerts the operator never opted into")
	}
}

func TestBuildInspectionEngineWiresTheAlerterWhenAlertsAreOn(t *testing.T) {
	originalEnabled, originalAlerts := config.InspectionsEnabled, config.InspectionsAlerts
	config.InspectionsEnabled, config.InspectionsAlerts = true, true
	t.Cleanup(func() {
		config.InspectionsEnabled, config.InspectionsAlerts = originalEnabled, originalAlerts
	})

	engine, err := buildInspectionEngine(NewMetrics(), stubFamilySource{},
		func(string, string) string { return "some-pod" },
		&fakeEventSink{}, logr.Discard())
	if err != nil {
		t.Fatalf("buildInspectionEngine: %v", err)
	}
	if engine == nil {
		t.Fatal("no engine built with inspections enabled")
	}
}

func TestBuildInspectionEngineWithAlertsOffStillExposesMetrics(t *testing.T) {
	originalEnabled, originalAlerts := config.InspectionsEnabled, config.InspectionsAlerts
	config.InspectionsEnabled, config.InspectionsAlerts = true, false
	t.Cleanup(func() {
		config.InspectionsEnabled, config.InspectionsAlerts = originalEnabled, originalAlerts
	})

	engine, err := buildInspectionEngine(NewMetrics(), stubFamilySource{}, nil, &fakeEventSink{}, logr.Discard())
	if err != nil {
		t.Fatalf("buildInspectionEngine: %v", err)
	}
	if engine == nil {
		t.Fatal("no engine built with alerts off")
	}
}

func TestBuildInspectionEngineToleratesNoEventWriter(t *testing.T) {
	originalEnabled, originalAlerts := config.InspectionsEnabled, config.InspectionsAlerts
	config.InspectionsEnabled, config.InspectionsAlerts = true, true
	t.Cleanup(func() {
		config.InspectionsEnabled, config.InspectionsAlerts = originalEnabled, originalAlerts
	})

	engine, err := buildInspectionEngine(NewMetrics(), stubFamilySource{}, nil, nil, logr.Discard())
	if err != nil {
		t.Fatalf("buildInspectionEngine with no event writer: %v", err)
	}
	if engine == nil {
		t.Fatal("no engine built")
	}
}

func TestBuildInspectionEngineReportsARegistrationCollision(t *testing.T) {
	originalEnabled := config.InspectionsEnabled
	config.InspectionsEnabled = true
	t.Cleanup(func() { config.InspectionsEnabled = originalEnabled })

	metrics := NewMetrics()
	if _, err := buildInspectionEngine(metrics, stubFamilySource{}, nil, &fakeEventSink{}, logr.Discard()); err != nil {
		t.Fatalf("first build: %v", err)
	}
	if _, err := buildInspectionEngine(metrics, stubFamilySource{}, nil, &fakeEventSink{}, logr.Discard()); err == nil {
		t.Error("a second engine on the same registry reported success; the duplicate " +
			"collector would fail every scrape")
	}
}

func TestInspectionThresholdsComeFromConfiguration(t *testing.T) {
	originalRate, originalMin := config.InspectionErrorRatePercent, config.InspectionMinRequestsPerSecond
	originalLatency := config.InspectionMeanLatency
	config.InspectionErrorRatePercent = 12
	config.InspectionMinRequestsPerSecond = 0.75
	config.InspectionMeanLatency = 2500 * time.Millisecond
	t.Cleanup(func() {
		config.InspectionErrorRatePercent = originalRate
		config.InspectionMinRequestsPerSecond = originalMin
		config.InspectionMeanLatency = originalLatency
	})

	got := inspectionThresholds()
	if got.ErrorRatePercent != 12 {
		t.Errorf("ErrorRatePercent = %v, want 12", got.ErrorRatePercent)
	}
	if got.MinRequestsPerSecond != 0.75 {
		t.Errorf("MinRequestsPerSecond = %v, want 0.75", got.MinRequestsPerSecond)
	}
	if got.MeanLatency != 2500*time.Millisecond {
		t.Errorf("MeanLatency = %v, want 2.5s", got.MeanLatency)
	}
	if got.UtilizationWarn != config.AlertWarnPct {
		t.Errorf("UtilizationWarn = %v, want the shared alert band %v",
			got.UtilizationWarn, config.AlertWarnPct)
	}
}

func TestRunInspectionsReturnsImmediatelyWithNoEngine(t *testing.T) {
	if err := runInspections(t.Context(), nil, logr.Discard()); err != nil {
		t.Errorf("runInspections with no engine: %v", err)
	}
}

func TestRunInspectionsEvaluatesOnItsIntervalAndStopsOnCancel(t *testing.T) {
	originalInterval := config.InspectionsInterval
	config.InspectionsInterval = 10 * time.Millisecond
	t.Cleanup(func() { config.InspectionsInterval = originalInterval })

	reg := prometheus.NewRegistry()
	engine, err := inspect.New(inspect.Options{
		Gatherer:   reg,
		Registerer: reg,
		Rules:      []inspect.Rule{},
		Thresholds: inspect.DefaultThresholds(),
	})
	if err != nil {
		t.Fatalf("inspect.New: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- runInspections(ctx, engine, logr.Discard()) }()

	deadline := time.After(2 * time.Second)
	for evaluationCount(t, reg) < 2 {
		select {
		case <-deadline:
			t.Fatalf("the loop evaluated %v times in 2s at a 10ms interval",
				evaluationCount(t, reg))
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runInspections returned %v on cancel, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("runInspections did not return after its context was cancelled")
	}
}

func TestRunInspectionsKeepsGoingAfterAFailedPass(t *testing.T) {
	originalInterval := config.InspectionsInterval
	config.InspectionsInterval = 10 * time.Millisecond
	t.Cleanup(func() { config.InspectionsInterval = originalInterval })

	reg := prometheus.NewRegistry()
	engine, err := inspect.New(inspect.Options{
		Gatherer:   brokenGatherer{},
		Registerer: reg,
		Rules:      []inspect.Rule{},
		Thresholds: inspect.DefaultThresholds(),
	})
	if err != nil {
		t.Fatalf("inspect.New: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if err := runInspections(ctx, engine, logr.Discard()); err != nil {
		t.Errorf("runInspections returned %v after repeated gather failures, want nil", err)
	}
	if got := failureCount(t, reg); got < 2 {
		t.Errorf("failures counted = %v; the loop stopped after the first error instead "+
			"of continuing and counting each one", got)
	}
}

type brokenGatherer struct{}

func (brokenGatherer) Gather() ([]*dto.MetricFamily, error) {
	return nil, errors.New("collector exploded")
}

func counterFromRegistry(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		return 0
	}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			return m.GetCounter().GetValue()
		}
	}
	return 0
}

func evaluationCount(t *testing.T, reg *prometheus.Registry) float64 {
	return counterFromRegistry(t, reg, "podtrace_inspections_evaluations_total")
}

func failureCount(t *testing.T, reg *prometheus.Registry) float64 {
	return counterFromRegistry(t, reg, "podtrace_inspections_failures_total")
}

func TestAnActivatedIssueIsLoggedByTheLoop(t *testing.T) {
	originalInterval := config.InspectionsInterval
	config.InspectionsInterval = 10 * time.Millisecond
	t.Cleanup(func() { config.InspectionsInterval = originalInterval })

	always := inspect.Rule{
		ID:    detector.IDResourceSaturation,
		For:   0,
		Query: "vector(1)",
		Eval: func(inspect.Window, inspect.Thresholds) []detector.Issue {
			return []detector.Issue{saturationIssue("pod-a")}
		},
	}
	reg := prometheus.NewRegistry()
	engine, err := inspect.New(inspect.Options{
		Gatherer:   reg,
		Registerer: reg,
		Rules:      []inspect.Rule{always},
		Thresholds: inspect.DefaultThresholds(),
	})
	if err != nil {
		t.Fatalf("inspect.New: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if err := runInspections(ctx, engine, logr.Discard()); err != nil {
		t.Fatalf("runInspections: %v", err)
	}

	if got := len(engine.Active()); got != 1 {
		t.Errorf("Active() = %d after the loop ran, want the issue to have activated", got)
	}
}

func liveManager(t *testing.T) (*alerting.Manager, *countingSender) {
	t.Helper()
	original := config.AlertingEnabled
	config.AlertingEnabled = true
	t.Cleanup(func() { config.AlertingEnabled = original })

	manager, err := alerting.NewManager()
	if err != nil {
		t.Fatalf("alerting.NewManager: %v", err)
	}
	relay := &countingSender{}
	manager.EnsureEnabledWithSender(relay)
	if !manager.IsEnabled() {
		t.Skip("the alert manager could not be enabled in this environment")
	}
	t.Cleanup(func() { _ = manager.Shutdown(context.Background()) })
	return manager, relay
}

func TestALiveManagerCarryingTheEventSinkIsTheOnlyWriter(t *testing.T) {
	originalEvents := config.AlertEventsEnabled
	config.AlertEventsEnabled = true
	t.Cleanup(func() { config.AlertEventsEnabled = originalEvents })

	manager, relay := liveManager(t)
	sink := &fakeEventSink{}
	alerter := &issueAlerter{events: sink, manager: manager, now: time.Now, logger: logr.Discard()}
	alerter.IssueActivated(saturationIssue("checkout-abc"))

	if len(sink.sent) != 0 {
		t.Errorf("the alerter wrote its own Event as well as routing through the manager; "+
			"one issue would trigger two sessions (%d direct writes)", len(sink.sent))
	}
	waitForCount(t, relay, 1, "the live manager never received the alert")
}

func TestAManagerWithoutTheEventSinkStillGetsTheAlertAndWeWriteTheEvent(t *testing.T) {
	originalEvents := config.AlertEventsEnabled
	config.AlertEventsEnabled = false
	t.Cleanup(func() { config.AlertEventsEnabled = originalEvents })

	manager, relay := liveManager(t)
	sink := &fakeEventSink{}
	alerter := &issueAlerter{events: sink, manager: manager, now: time.Now, logger: logr.Discard()}
	alerter.IssueActivated(saturationIssue("checkout-abc"))

	if len(sink.sent) != 1 {
		t.Errorf("wrote %d trigger Events, want 1; the manager cannot write one with "+
			"alert-Events off, so the issue could not start a session", len(sink.sent))
	}
	waitForCount(t, relay, 1, "the alert was withheld from the manager's other sinks")
}

func waitForCount(t *testing.T, relay *countingSender, want int, msg string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for relay.count() < want {
		select {
		case <-deadline:
			t.Fatalf("%s (saw %d, want %d)", msg, relay.count(), want)
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

type countingSender struct {
	mu sync.Mutex
	n  int
}

func (c *countingSender) Name() string { return "counting" }

func (c *countingSender) Send(context.Context, *alerting.Alert) error {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return nil
}

func (c *countingSender) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

type stubFamilySource struct{}

func (stubFamilySource) CollectFamilies([]string) map[string][]*dto.Metric { return nil }

func (stubFamilySource) RuleFamilies() []string { return nil }

func TestInspectionThresholdsCarryTheConfiguredHoldTime(t *testing.T) {
	original := config.InspectionsHoldTime
	config.InspectionsHoldTime = 20 * time.Second
	t.Cleanup(func() { config.InspectionsHoldTime = original })

	if got := inspectionThresholds().HoldTime; got != 20*time.Second {
		t.Errorf("HoldTime = %v, want the configured 20s; the CRD field would not reach "+
			"the engine", got)
	}
}
