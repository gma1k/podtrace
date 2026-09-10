package workloadmetrics

import (
	"strings"
	"testing"
	"time"

	"errors"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/gma1k/podtrace/internal/events"
)

func replica(pod string) *events.K8sMetadata {
	meta := enriched()
	meta.PodName = pod
	return meta
}

func resourceEvent(pod string, kind uint32, pct int32) *events.Event {
	return &events.Event{
		Type:     events.EventResourceLimit,
		TCPState: kind,
		Error:    pct,
		K8s:      replica(pod),
	}
}

func connectionEvent(t events.EventType, target string) *events.Event {
	return &events.Event{Type: t, Target: target, K8s: enriched()}
}

func exportAll(t *testing.T, sink *Sink, evs ...*events.Event) {
	t.Helper()
	if err := sink.Export(t.Context(), evs); err != nil {
		t.Fatalf("Export: %v", err)
	}
}

func TestUtilizationIsReportedPerResource(t *testing.T) {
	sink, reg := newTestSink(t, 0)
	exportAll(t, sink,
		resourceEvent("checkout-a", 0, 91),
		resourceEvent("checkout-a", 1, 44),
		resourceEvent("checkout-a", 2, 7),
		resourceEvent("checkout-a", 99, 12),
	)

	got := map[string]float64{}
	for _, m := range gather(t, reg, "podtrace_workload_resource_utilization_percent") {
		got[labelsOf(m)["resource"]] = m.GetGauge().GetValue()
	}

	for resource, want := range map[string]float64{
		"cpu": 91, "memory": 44, "io": 7, "other": 12,
	} {
		if got[resource] != want {
			t.Errorf("resource=%q utilization = %v, want %v (all: %v)",
				resource, got[resource], want, got)
		}
	}
}

func TestASaturatedReplicaIsNotHiddenByAHealthyOne(t *testing.T) {
	sink, reg := newTestSink(t, 0)
	exportAll(t, sink,
		resourceEvent("checkout-hot", 0, 98),
		resourceEvent("checkout-cold", 0, 5),
	)

	metrics := gather(t, reg, "podtrace_workload_resource_utilization_percent")
	if len(metrics) != 1 {
		t.Fatalf("got %d series, want 1; this family is workload-scoped", len(metrics))
	}
	if got := metrics[0].GetGauge().GetValue(); got != 98 {
		t.Errorf("utilization = %v, want the held peak 98; the healthy replica erased the "+
			"saturated one, which is invisible exactly when it matters", got)
	}
}

func TestNoSaturationFamilyCarriesAPodLabelUnlessOptedIn(t *testing.T) {
	sink, reg := newTestSink(t, 0)
	exportAll(t, sink,
		resourceEvent("checkout-a", 0, 91),
		connectionEvent(events.EventPoolAcquire, "postgresql-pool"),
	)

	for _, family := range []string{
		"podtrace_workload_resource_utilization_percent",
		"podtrace_workload_db_connections_opened_total",
	} {
		for _, m := range gather(t, reg, family) {
			if _, present := labelsOf(m)["pod"]; present {
				t.Errorf("%s carries a pod label without being opted in: %v",
					family, labelsOf(m))
			}
			if _, present := labelsOf(m)["process"]; present {
				t.Errorf("%s carries a process label without being opted in", family)
			}
		}
	}
}

func TestAHeldPeakDecaysSoRecoveryIsVisible(t *testing.T) {
	clock := time.Now()
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	exportAll(t, sink, resourceEvent("checkout-a", 0, 97))
	exportAll(t, sink, resourceEvent("checkout-a", 0, 4))
	if got := gather(t, reg, "podtrace_workload_resource_utilization_percent")[0].GetGauge().GetValue(); got != 97 {
		t.Fatalf("utilization = %v inside the hold window, want the peak 97", got)
	}

	clock = clock.Add(utilizationHoldWindow + time.Second)
	exportAll(t, sink, resourceEvent("checkout-a", 0, 4))
	if got := gather(t, reg, "podtrace_workload_resource_utilization_percent")[0].GetGauge().GetValue(); got != 4 {
		t.Errorf("utilization = %v after the hold window, want the newer 4; a peak held "+
			"forever pins a recovered workload at its worst reading", got)
	}
}

func TestAReapedSeriesDoesNotResurrectItsPeak(t *testing.T) {
	clock := time.Now()
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	exportAll(t, sink, resourceEvent("checkout-a", 0, 96))
	clock = clock.Add(20 * time.Minute)
	if n := sink.Reap(15 * time.Minute); n == 0 {
		t.Fatal("Reap removed nothing")
	}

	exportAll(t, sink, resourceEvent("checkout-a", 0, 3))
	if got := gather(t, reg, "podtrace_workload_resource_utilization_percent")[0].GetGauge().GetValue(); got != 3 {
		t.Errorf("utilization = %v after the series was reaped, want 3; the old peak was "+
			"resurrected from a stale map entry", got)
	}
}

func TestANonPhysicalUtilizationIsNotReported(t *testing.T) {
	sink, reg := newTestSink(t, 0)
	exportAll(t, sink, resourceEvent("checkout-a", 0, -5))

	if metrics := gather(t, reg, "podtrace_workload_resource_utilization_percent"); len(metrics) != 0 {
		t.Errorf("a negative utilization was reported as %v; it would read as healthy "+
			"and mask a real reading", metrics)
	}
}

func TestUtilizationAboveTheLimitIsStillReported(t *testing.T) {
	sink, reg := newTestSink(t, 0)
	exportAll(t, sink, resourceEvent("checkout-a", 1, 140))

	metrics := gather(t, reg, "podtrace_workload_resource_utilization_percent")
	if len(metrics) != 1 || metrics[0].GetGauge().GetValue() != 140 {
		t.Errorf("utilization over 100 was not reported verbatim: %v", metrics)
	}
}

func TestConnectionCountersSeparateOpensFromCloses(t *testing.T) {
	sink, reg := newTestSink(t, 0)
	exportAll(t, sink,
		connectionEvent(events.EventPoolAcquire, "postgresql-pool"),
		connectionEvent(events.EventPoolAcquire, "postgresql-pool"),
		connectionEvent(events.EventPoolAcquire, "postgresql-pool"),
		connectionEvent(events.EventPoolRelease, "postgresql-pool"),
	)

	for name, want := range map[string]float64{
		"podtrace_workload_db_connections_opened_total": 3,
		"podtrace_workload_db_connections_closed_total": 1,
	} {
		metrics := gather(t, reg, name)
		if len(metrics) != 1 {
			t.Fatalf("%s: got %d series, want 1", name, len(metrics))
		}
		if got := metrics[0].GetCounter().GetValue(); got != want {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
		if got := labelsOf(metrics[0])["db_system"]; got != "postgresql" {
			t.Errorf("%s db_system = %q, want postgresql", name, got)
		}
	}

	open := gather(t, reg, "podtrace_workload_db_connections_opened_total")[0].GetCounter().GetValue() -
		gather(t, reg, "podtrace_workload_db_connections_closed_total")[0].GetCounter().GetValue()
	if open != 2 {
		t.Errorf("connections open = %v, want 2", open)
	}
}

func TestNoFamilyClaimsToMeasurePoolExhaustion(t *testing.T) {
	sink, reg := newTestSink(t, 0)
	exportAll(t, sink,
		connectionEvent(events.EventPoolExhausted, "postgresql-pool"),
		connectionEvent(events.EventPoolExhausted, "postgresql-pool"),
	)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range families {
		name := f.GetName()
		if strings.Contains(name, "pool_exhausted") || strings.Contains(name, "pool_wait") {
			t.Errorf("%s is exported; it would report connection age as pool wait time", name)
		}
	}
}

func TestSaturationSurvivesKernelAggregation(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{KernelAggregation: true, Lookup: kernelTestLookup})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	exportAll(t, sink,
		resourceEvent("checkout-a", 0, 88),
		connectionEvent(events.EventPoolAcquire, "postgresql-pool"),
	)

	for _, name := range []string{
		"podtrace_workload_resource_utilization_percent",
		"podtrace_workload_db_connections_opened_total",
	} {
		if len(gather(t, reg, name)) == 0 {
			t.Errorf("%s went dark under kernel aggregation", name)
		}
	}
}

func TestADepartedWorkloadStopsLookingSaturated(t *testing.T) {
	clock := time.Now()
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	exportAll(t, sink, resourceEvent("checkout-a", 0, 97))

	if len(gather(t, reg, "podtrace_workload_resource_utilization_percent")) != 1 {
		t.Fatal("the gauge was never recorded")
	}

	clock = clock.Add(20 * time.Minute)
	if removed := sink.Reap(15 * time.Minute); removed == 0 {
		t.Fatal("Reap removed nothing")
	}

	if metrics := gather(t, reg, "podtrace_workload_resource_utilization_percent"); len(metrics) != 0 {
		t.Errorf("the gauge survived reaping as %v; a departed pod would stay pinned at "+
			"97%% and alert forever", metrics)
	}
}

func TestDBSystemLabelCoversEveryLibraryTheProbesHook(t *testing.T) {

	for target, want := range map[string]string{
		"postgresql-pool": "postgresql",
		"mysql-pool":      "mysql",
		"sqlite-pool":     "sqlite",
		"default-pool":    "other",
		"":                "other",
		"something-new":   "other",
	} {
		if got := dbSystemLabel(target); got != want {
			t.Errorf("dbSystemLabel(%q) = %q, want %q", target, got, want)
		}
	}
}

func TestResourceLabelCoversEveryKindTheBPFSideEncodes(t *testing.T) {
	for kind, want := range map[uint32]string{0: "cpu", 1: "memory", 2: "io", 3: "other", 99: "other"} {
		if got := resourceLabel(kind); got != want {
			t.Errorf("resourceLabel(%d) = %q, want %q", kind, got, want)
		}
	}
}

func TestConnectionCounterClaimsOnlyTheTwoLifecycleEvents(t *testing.T) {
	sink, _ := newTestSink(t, 0)

	if _, _, ok := sink.connectionCounter(events.EventPoolExhausted); ok {
		t.Error("the exhausted event resolved to a counter; it reports connection age, " +
			"not pool wait, so no honest metric can carry it")
	}
	if _, _, ok := sink.connectionCounter(events.EventHTTPResp); ok {
		t.Error("an unrelated event type resolved to a connection counter")
	}
	for _, tc := range []struct {
		typ  events.EventType
		want string
	}{
		{events.EventPoolAcquire, "db_connections_opened_total"},
		{events.EventPoolRelease, "db_connections_closed_total"},
	} {
		counter, family, ok := sink.connectionCounter(tc.typ)
		if !ok || family != tc.want || counter == nil {
			t.Errorf("connectionCounter(%v) = %v,%q,%v; want a counter under %q",
				tc.typ, counter, family, ok, tc.want)
		}
	}
}

func TestEveryConnectionFamilyIsEvictable(t *testing.T) {

	sink, _ := newTestSink(t, 0)
	for _, typ := range []events.EventType{events.EventPoolAcquire, events.EventPoolRelease} {
		_, family, ok := sink.connectionCounter(typ)
		if !ok {
			t.Fatalf("connectionCounter(%v) resolved nothing", typ)
		}
		if _, ok := sink.c.deleterFor(family); !ok {
			t.Errorf("family %q is admitted but the reaper cannot resolve it", family)
		}
	}
}

func TestRecordSaturationDeclinesEventsThatAreNotItsOwn(t *testing.T) {
	sink, _ := newTestSink(t, 0)
	base, ok := sink.baseLabelValues(&events.Event{Type: events.EventHTTPResp, K8s: enriched()})
	if !ok {
		t.Fatal("fixture is unattributed")
	}
	for _, typ := range []events.EventType{events.EventHTTPResp, events.EventDNS, events.EventPoolExhausted} {
		if sink.recordSaturation(&events.Event{Type: typ, K8s: enriched()}, base) {
			t.Errorf("recordSaturation claimed %v; only the resource and connection "+
				"lifecycle events belong to it", typ)
		}
	}
}

func TestAnUnattributableResourceEventIsNotRecorded(t *testing.T) {

	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{Lookup: func(uint64) (events.K8sMetadata, bool) {
		return events.K8sMetadata{}, false
	}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := sink.Export(t.Context(), []*events.Event{
		{Type: events.EventResourceLimit, TCPState: 0, Error: 95},
	}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if got := gather(t, reg, "podtrace_workload_resource_utilization_percent"); len(got) != 0 {
		t.Errorf("an unattributable reading was recorded as %v", got)
	}
}

func TestSetGaugeRespectsTheSeriesBudget(t *testing.T) {

	sink, reg := newTestSink(t, 1)
	for _, res := range []uint32{0, 1, 2} {
		exportAll(t, sink, resourceEvent("pod-a", res, 90))
	}
	if got := len(gather(t, reg, "podtrace_workload_resource_utilization_percent")); got > 1 {
		t.Errorf("got %d series at a budget of 1", got)
	}
	if len(gather(t, reg, "podtrace_workload_metrics_series_dropped_total")) == 0 {
		t.Error("series past the budget were admitted without being counted as dropped")
	}
}

func TestCollectFamiliesServesEveryFamilyTheRulesAskFor(t *testing.T) {
	sink, _ := newTestSink(t, 0)
	exportAll(t, sink,
		&events.Event{Type: events.EventHTTPResp, CgroupID: kernelTestCgroup,
			LatencyNS: 2_000_000, Details: "200", K8s: enriched()},
		resourceEvent("pod-a", 0, 91),
	)

	names := sink.RuleFamilies()
	if len(names) == 0 {
		t.Fatal("RuleFamilies() is empty; the engine would read nothing")
	}
	got := sink.CollectFamilies(names)
	for _, name := range names {
		if _, ok := sink.collectorFor(name); !ok {
			t.Errorf("the rules ask for %q but this plane owns no collector for it", name)
		}
	}
	if len(got) == 0 {
		t.Error("CollectFamilies returned nothing for families that have series")
	}
}

func TestCollectFamiliesSkipsNamesThisPlaneDoesNotOwn(t *testing.T) {
	sink, _ := newTestSink(t, 0)
	got := sink.CollectFamilies([]string{
		"podtrace_workload_not_a_real_family",
		"some_other_exporter_metric_total",
		"",
	})
	if len(got) != 0 {
		t.Errorf("unknown families resolved to %v; a rule naming one must get no samples "+
			"rather than a spurious series", got)
	}
}

func TestCollectFamiliesReadsTheSameValuesAScrapeWould(t *testing.T) {
	sink, reg := newTestSink(t, 0)
	for i := 0; i < 7; i++ {
		exportAll(t, sink, &events.Event{Type: events.EventHTTPResp, CgroupID: kernelTestCgroup,
			LatencyNS: 1_000_000, Details: "200", K8s: enriched()})
	}

	scraped := gather(t, reg, "podtrace_workload_l7_requests_total")
	if len(scraped) == 0 {
		t.Fatal("nothing was scraped")
	}
	var scrapedTotal float64
	for _, m := range scraped {
		scrapedTotal += m.GetCounter().GetValue()
	}

	collected := sink.CollectFamilies([]string{"podtrace_workload_l7_requests_total"})
	var collectedTotal float64
	for _, m := range collected["podtrace_workload_l7_requests_total"] {
		collectedTotal += m.GetCounter().GetValue()
	}

	if collectedTotal != scrapedTotal {
		t.Errorf("scoped collect saw %v, a scrape saw %v.\n\nAn inspection and a dashboard "+
			"must never disagree about a value, or a firing rule cannot be reproduced by "+
			"running its own query.", collectedTotal, scrapedTotal)
	}
}

type unserialisableMetric struct{ desc *prometheus.Desc }

func (m unserialisableMetric) Desc() *prometheus.Desc { return m.desc }

func (m unserialisableMetric) Write(*dto.Metric) error { return errors.New("cannot serialise") }

type oneBadMetricCollector struct{ good prometheus.Collector }

func (c oneBadMetricCollector) Describe(ch chan<- *prometheus.Desc) { c.good.Describe(ch) }

func (c oneBadMetricCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- unserialisableMetric{desc: prometheus.NewDesc("broken", "broken", nil, nil)}
	c.good.Collect(ch)
}

func TestOneUnserialisableSeriesDoesNotBlindTheRest(t *testing.T) {
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "x_total"}, []string{"w"})
	counter.WithLabelValues("a").Inc()
	counter.WithLabelValues("b").Inc()

	got := collectInto(oneBadMetricCollector{good: counter})
	if len(got) != 2 {
		t.Errorf("collected %d metrics, want the 2 good ones; a single series that will "+
			"not serialise must not take the whole family with it", len(got))
	}
}
