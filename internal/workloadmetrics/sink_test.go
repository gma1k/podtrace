package workloadmetrics

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/gma1k/podtrace/internal/events"
)

func newTestSink(t *testing.T, budget int) (*Sink, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{SeriesBudget: budget, NativeHistograms: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return sink, reg
}

func gather(t *testing.T, reg *prometheus.Registry, name string) []*dto.Metric {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() == name {
			return f.GetMetric()
		}
	}
	return nil
}

func labelsOf(m *dto.Metric) map[string]string {
	out := map[string]string{}
	for _, lp := range m.GetLabel() {
		out[lp.GetName()] = lp.GetValue()
	}
	return out
}

func enriched() *events.K8sMetadata {
	return &events.K8sMetadata{
		Namespace:     "shop",
		PodName:       "checkout-7d9f8b6c5d-x4k2p",
		PodUID:        "uid-1",
		NodeName:      "node-a",
		ContainerName: "checkout",
		WorkloadKind:  "Deployment",
		WorkloadName:  "checkout",
	}
}

func TestLabelsCarryWorkloadIdentityNotPodOrProcess(t *testing.T) {
	sink, reg := newTestSink(t, 0)

	err := sink.Export(context.Background(), []*events.Event{{
		Type:        events.EventTCPSend,
		LatencyNS:   2_000_000,
		Bytes:       512,
		ProcessName: "checkout-server",
		K8s:         enriched(),
	}})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	metrics := gather(t, reg, "podtrace_workload_network_bytes_total")
	if len(metrics) != 1 {
		t.Fatalf("want 1 series, got %d", len(metrics))
	}

	got := labelsOf(metrics[0])
	for _, banned := range []string{"pod", "target_pod", "process_name", "pod_name"} {
		if _, present := got[banned]; present {
			t.Errorf("label %q must not appear on the continuous surface; it churns a new series per rollout", banned)
		}
	}

	for key, want := range map[string]string{
		"namespace":     "shop",
		"workload":      "checkout",
		"workload_kind": "Deployment",
		"container":     "checkout",
		"direction":     "egress",
		"transport":     "tcp",
	} {
		if got[key] != want {
			t.Errorf("label %q = %q, want %q", key, got[key], want)
		}
	}
}

func TestUnattributedEventsAreCountedNotAggregated(t *testing.T) {
	sink, reg := newTestSink(t, 0)

	err := sink.Export(context.Background(), []*events.Event{
		{Type: events.EventTCPSend, LatencyNS: 1000, Bytes: 1, K8s: nil},
		{Type: events.EventTCPSend, LatencyNS: 1000, Bytes: 1, K8s: &events.K8sMetadata{}},
		{Type: events.EventTCPSend, LatencyNS: 1000, Bytes: 1, K8s: &events.K8sMetadata{PodName: "orphan"}},
	})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	if got := gather(t, reg, "podtrace_workload_network_bytes_total"); len(got) != 0 {
		t.Fatalf("unattributed events must not create series, got %d", len(got))
	}

	var unattributed float64
	for _, m := range gather(t, reg, "podtrace_workload_metrics_events_total") {
		if labelsOf(m)["outcome"] == "unattributed" {
			unattributed = m.GetCounter().GetValue()
		}
	}
	if unattributed != 3 {
		t.Errorf("unattributed count = %v, want 3", unattributed)
	}
}

func TestSeriesBudgetRefusesNewSeriesAndCountsTheDrop(t *testing.T) {
	sink, reg := newTestSink(t, 2)

	var batch []*events.Event
	for _, workload := range []string{"a", "b", "c", "d"} {
		meta := enriched()
		meta.WorkloadName = workload
		batch = append(batch, &events.Event{
			Type:      events.EventDNS,
			LatencyNS: 1_000_000,
			K8s:       meta,
		})
	}
	if err := sink.Export(context.Background(), batch); err != nil {
		t.Fatalf("Export: %v", err)
	}

	series := gather(t, reg, "podtrace_workload_dns_latency_seconds")
	if len(series) != 2 {
		t.Fatalf("budget of 2 admitted %d series", len(series))
	}

	var dropped float64
	for _, m := range gather(t, reg, "podtrace_workload_metrics_series_dropped_total") {
		if labelsOf(m)["family"] == "dns_latency_seconds" {
			dropped = m.GetCounter().GetValue()
		}
	}
	if dropped != 2 {
		t.Errorf("dropped = %v, want 2", dropped)
	}

	active := gather(t, reg, "podtrace_workload_metrics_series_active")
	if len(active) != 1 || active[0].GetGauge().GetValue() != 2 {
		t.Errorf("series_active did not settle at the budget: %+v", active)
	}
}

func TestBudgetAdmitsRepeatObservationsOfAKnownSeries(t *testing.T) {
	sink, reg := newTestSink(t, 1)

	var batch []*events.Event
	for i := 0; i < 50; i++ {
		batch = append(batch, &events.Event{
			Type:      events.EventDNS,
			LatencyNS: 1_000_000,
			K8s:       enriched(),
		})
	}
	if err := sink.Export(context.Background(), batch); err != nil {
		t.Fatalf("Export: %v", err)
	}

	series := gather(t, reg, "podtrace_workload_dns_latency_seconds")
	if len(series) != 1 {
		t.Fatalf("want 1 series, got %d", len(series))
	}
	if got := series[0].GetHistogram().GetSampleCount(); got != 50 {
		t.Errorf("sample count = %d, want 50; the budget must cap distinct series, not observations", got)
	}
	if len(gather(t, reg, "podtrace_workload_metrics_series_dropped_total")) != 0 {
		t.Error("repeat observations of an admitted series must not count as drops")
	}
}

func TestSuccessfulL7ResponseIsNotAnError(t *testing.T) {
	sink, reg := newTestSink(t, 0)

	err := sink.Export(context.Background(), []*events.Event{{
		Type:      events.EventHTTPResp,
		LatencyNS: 5_000_000,
		Details:   "200",
		Error:     0,
		K8s:       enriched(),
	}})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	metrics := gather(t, reg, "podtrace_workload_l7_requests_total")
	if len(metrics) != 1 {
		t.Fatalf("want 1 series, got %d", len(metrics))
	}
	got := labelsOf(metrics[0])
	if got["status_class"] != "2xx" {
		t.Errorf("status_class = %q, want 2xx", got["status_class"])
	}
	if got["outcome"] != "ok" {
		t.Errorf("outcome = %q, want ok; a 200 response must never count as an error", got["outcome"])
	}
	if len(gather(t, reg, "podtrace_workload_errors_total")) != 0 {
		t.Error("a 200 response incremented errors_total")
	}
}

func TestServerErrorIsCountedAsError(t *testing.T) {
	sink, reg := newTestSink(t, 0)

	err := sink.Export(context.Background(), []*events.Event{{
		Type:      events.EventHTTPResp,
		LatencyNS: 5_000_000,
		Error:     503,
		K8s:       enriched(),
	}})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	metrics := gather(t, reg, "podtrace_workload_l7_requests_total")
	if len(metrics) != 1 {
		t.Fatalf("want 1 series, got %d", len(metrics))
	}
	got := labelsOf(metrics[0])
	if got["status_class"] != "5xx" {
		t.Errorf("status_class = %q, want 5xx", got["status_class"])
	}
	if got["outcome"] != "error" {
		t.Errorf("outcome = %q, want error", got["outcome"])
	}

	errs := gather(t, reg, "podtrace_workload_errors_total")
	if len(errs) != 1 || labelsOf(errs[0])["kind"] != "l7" {
		t.Errorf("errors_total did not record an l7 error: %+v", errs)
	}
}

func TestHTTP3KeepsItsOwnProtocolLabel(t *testing.T) {
	sink, reg := newTestSink(t, 0)

	err := sink.Export(context.Background(), []*events.Event{{
		Type:      events.EventHTTPResp,
		LatencyNS: 3_000_000,
		TCPState:  events.HTTPTransportH3,
		Details:   "200",
		K8s:       enriched(),
	}})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	metrics := gather(t, reg, "podtrace_workload_l7_requests_total")
	if len(metrics) != 1 {
		t.Fatalf("want 1 series, got %d", len(metrics))
	}
	if got := labelsOf(metrics[0])["protocol"]; got != "http3" {
		t.Errorf("protocol = %q, want http3; collapsing h3 into http discards podtrace's distinguishing coverage", got)
	}
}

func TestUnmappedEventTypeIsIgnoredNotDropped(t *testing.T) {
	sink, reg := newTestSink(t, 0)

	err := sink.Export(context.Background(), []*events.Event{{
		Type:      events.EventExec,
		LatencyNS: 1000,
		K8s:       enriched(),
	}})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	var ignored float64
	for _, m := range gather(t, reg, "podtrace_workload_metrics_events_total") {
		if labelsOf(m)["outcome"] == "ignored" {
			ignored = m.GetCounter().GetValue()
		}
	}
	if ignored != 1 {
		t.Errorf("ignored = %v, want 1", ignored)
	}
}

func TestNoLatestValueGaugesOnTheContinuousSurface(t *testing.T) {
	_, reg := newTestSink(t, 0)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range families {
		name := f.GetName()
		if f.GetType() != dto.MetricType_GAUGE {
			continue
		}
		if name == "podtrace_workload_metrics_series_active" {
			continue
		}
		t.Errorf("%s is a gauge; latency on a permanently scraped surface must be a "+
			"histogram, since a last-observed value is a sample of one at scrape time", name)
	}
}

func TestExportToleratesNilEventsAndEmptyBatches(t *testing.T) {
	sink, _ := newTestSink(t, 0)

	if err := sink.Export(context.Background(), nil); err != nil {
		t.Fatalf("empty batch: %v", err)
	}
	if err := sink.Export(context.Background(), []*events.Event{nil, nil}); err != nil {
		t.Fatalf("nil events: %v", err)
	}
}

func TestSinkSatisfiesExporterContract(t *testing.T) {
	sink, _ := newTestSink(t, 0)

	if sink.Name() == "" {
		t.Error("Name must be non-empty; the engine logs it per exporter")
	}
	if err := sink.Close(context.Background()); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestUnenrichedEventsAreAttributedThroughLookup(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{
		Lookup: func(cgroupID uint64) (events.K8sMetadata, bool) {
			if cgroupID != 4242 {
				return events.K8sMetadata{}, false
			}
			return *enriched(), true
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := sink.Export(context.Background(), []*events.Event{{
		Type:      events.EventDNS,
		LatencyNS: 1_000_000,
		CgroupID:  4242,
		K8s:       nil,
	}}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	series := gather(t, reg, "podtrace_workload_dns_latency_seconds")
	if len(series) != 1 {
		t.Fatalf("want 1 series from an unenriched event, got %d; the sink must not "+
			"depend on another exporter having enriched the batch first", len(series))
	}
	if got := labelsOf(series[0])["workload"]; got != "checkout" {
		t.Errorf("workload = %q, want checkout", got)
	}
}

func TestLookupMissResolvesToUnattributed(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{
		Lookup: func(uint64) (events.K8sMetadata, bool) {
			return events.K8sMetadata{}, false
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := sink.Export(context.Background(), []*events.Event{{
		Type: events.EventDNS, LatencyNS: 1000, CgroupID: 7,
	}}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	if got := gather(t, reg, "podtrace_workload_dns_latency_seconds"); len(got) != 0 {
		t.Errorf("a lookup miss must not create a series, got %d", len(got))
	}
	var unattributed float64
	for _, m := range gather(t, reg, "podtrace_workload_metrics_events_total") {
		if labelsOf(m)["outcome"] == "unattributed" {
			unattributed = m.GetCounter().GetValue()
		}
	}
	if unattributed != 1 {
		t.Errorf("unattributed = %v, want 1", unattributed)
	}
}

func TestPreEnrichedEventDoesNotConsultLookup(t *testing.T) {
	reg := prometheus.NewRegistry()
	var calls int
	sink, err := New(reg, Options{
		Lookup: func(uint64) (events.K8sMetadata, bool) {
			calls++
			return events.K8sMetadata{}, false
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := sink.Export(context.Background(), []*events.Event{{
		Type: events.EventDNS, LatencyNS: 1000, CgroupID: 9, K8s: enriched(),
	}}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	if calls != 0 {
		t.Errorf("Lookup called %d times for an already-enriched event; the router's "+
			"work should not be repeated", calls)
	}
}

func TestOptInLabelsAppearOnlyWhenRequested(t *testing.T) {
	for _, tc := range []struct {
		name  string
		opts  Options
		want  []string
		avoid []string
	}{
		{
			name:  "default",
			opts:  Options{},
			avoid: []string{"pod", "process"},
		},
		{
			name:  "pod only",
			opts:  Options{IncludePodLabel: true},
			want:  []string{"pod"},
			avoid: []string{"process"},
		},
		{
			name: "both",
			opts: Options{IncludePodLabel: true, IncludeProcessLabel: true},
			want: []string{"pod", "process"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			sink, err := New(reg, tc.opts)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if err := sink.Export(context.Background(), []*events.Event{{
				Type:        events.EventDNS,
				LatencyNS:   1_000_000,
				ProcessName: "checkout-server",
				K8s:         enriched(),
			}}); err != nil {
				t.Fatalf("Export: %v", err)
			}

			series := gather(t, reg, "podtrace_workload_dns_latency_seconds")
			if len(series) != 1 {
				t.Fatalf("want 1 series, got %d", len(series))
			}
			got := labelsOf(series[0])

			for _, key := range tc.want {
				if _, present := got[key]; !present {
					t.Errorf("label %q missing when opted in", key)
				}
			}
			for _, key := range tc.avoid {
				if _, present := got[key]; present {
					t.Errorf("label %q present without being opted in", key)
				}
			}
			if got["pod"] != "" && got["pod"] != "checkout-7d9f8b6c5d-x4k2p" {
				t.Errorf("pod = %q, want the pod name", got["pod"])
			}
			if got["process"] != "" && got["process"] != "checkout-server" {
				t.Errorf("process = %q, want the process name", got["process"])
			}
		})
	}
}

func TestBudgetRefusesCounterSeriesToo(t *testing.T) {
	sink, reg := newTestSink(t, 1)

	var batch []*events.Event
	for _, workload := range []string{"a", "b", "c"} {
		meta := enriched()
		meta.WorkloadName = workload
		batch = append(batch, &events.Event{
			Type:      events.EventTCPSend,
			LatencyNS: 1_000_000,
			Bytes:     4096,
			K8s:       meta,
		})
	}
	if err := sink.Export(context.Background(), batch); err != nil {
		t.Fatalf("Export: %v", err)
	}

	bytes := gather(t, reg, "podtrace_workload_network_bytes_total")
	if len(bytes) > 1 {
		t.Errorf("budget of 1 admitted %d counter series; the chokepoint must apply "+
			"to counters as well as histograms, and counters back the two families "+
			"that matter most", len(bytes))
	}

	var dropped float64
	for _, m := range gather(t, reg, "podtrace_workload_metrics_series_dropped_total") {
		dropped += m.GetCounter().GetValue()
	}
	if dropped == 0 {
		t.Error("no drops recorded despite exceeding the budget")
	}
}

func TestBudgetExhaustionNotifiesExactlyOnce(t *testing.T) {
	var calls int
	var seenBudget int

	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{
		SeriesBudget: 1,
		OnBudgetExhausted: func(budget int) {
			calls++
			seenBudget = budget
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var batch []*events.Event
	for _, workload := range []string{"a", "b", "c", "d", "e"} {
		meta := enriched()
		meta.WorkloadName = workload
		batch = append(batch, &events.Event{
			Type: events.EventDNS, LatencyNS: 1_000_000, K8s: meta,
		})
	}
	if err := sink.Export(context.Background(), batch); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if err := sink.Export(context.Background(), batch); err != nil {
		t.Fatalf("second Export: %v", err)
	}

	if calls != 1 {
		t.Errorf("notified %d times, want exactly 1; this fires an error log, so "+
			"per-batch notification would flood the agent log", calls)
	}
	if seenBudget != 1 {
		t.Errorf("reported budget %d, want 1", seenBudget)
	}
}

func TestUnlimitedBudgetSkipsTheChokepointEntirely(t *testing.T) {
	sink, reg := newTestSink(t, 0)

	var batch []*events.Event
	for i := 0; i < 200; i++ {
		meta := enriched()
		meta.WorkloadName = fmt.Sprintf("w%d", i)
		batch = append(batch, &events.Event{
			Type: events.EventDNS, LatencyNS: 1_000_000, K8s: meta,
		})
	}
	if err := sink.Export(context.Background(), batch); err != nil {
		t.Fatalf("Export: %v", err)
	}

	if got := len(gather(t, reg, "podtrace_workload_dns_latency_seconds")); got != 200 {
		t.Errorf("got %d series, want 200 with the budget disabled", got)
	}
	if len(gather(t, reg, "podtrace_workload_metrics_series_dropped_total")) != 0 {
		t.Error("drops recorded with the budget disabled")
	}
}

func TestIdleSeriesAreEvictedAndBudgetFreed(t *testing.T) {
	clock := time.Now()
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{
		SeriesBudget: 2,
		Now:          func() time.Time { return clock },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	send := func(workload string) {
		meta := enriched()
		meta.WorkloadName = workload
		if err := sink.Export(context.Background(), []*events.Event{{
			Type: events.EventDNS, LatencyNS: 1_000_000, K8s: meta,
		}}); err != nil {
			t.Fatalf("Export: %v", err)
		}
	}

	send("gone-a")
	send("gone-b")
	if got := len(gather(t, reg, "podtrace_workload_dns_latency_seconds")); got != 2 {
		t.Fatalf("want 2 series, got %d", got)
	}

	send("still-here")
	if len(gather(t, reg, "podtrace_workload_metrics_series_dropped_total")) == 0 {
		t.Fatal("a third workload should have been refused at a budget of 2")
	}

	clock = clock.Add(20 * time.Minute)
	if n := sink.Reap(15 * time.Minute); n != 2 {
		t.Fatalf("reaped %d, want 2", n)
	}

	if got := len(gather(t, reg, "podtrace_workload_dns_latency_seconds")); got != 0 {
		t.Errorf("evicted series are still exposed (%d); a series that merely stops "+
			"updating keeps answering instant queries with a stale value", got)
	}

	send("new-workload")
	series := gather(t, reg, "podtrace_workload_dns_latency_seconds")
	if len(series) != 1 || labelsOf(series[0])["workload"] != "new-workload" {
		t.Errorf("a live workload was not admitted after eviction freed budget: %+v", series)
	}

	reaped := gather(t, reg, "podtrace_workload_metrics_series_reaped_total")
	if len(reaped) != 1 || reaped[0].GetCounter().GetValue() != 2 {
		t.Errorf("reaped counter = %+v, want 2", reaped)
	}
}

func TestActiveSeriesSurviveReaping(t *testing.T) {
	clock := time.Now()
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := 0; i < 3; i++ {
		if err := sink.Export(context.Background(), []*events.Event{{
			Type: events.EventDNS, LatencyNS: 1_000_000, K8s: enriched(),
		}}); err != nil {
			t.Fatalf("Export: %v", err)
		}
		clock = clock.Add(10 * time.Minute)
	}

	if n := sink.Reap(15 * time.Minute); n != 0 {
		t.Errorf("reaped %d series that were observed 10 minutes ago; only series "+
			"idle beyond the TTL may go", n)
	}
	if got := len(gather(t, reg, "podtrace_workload_dns_latency_seconds")); got != 1 {
		t.Errorf("want the live series retained, got %d", got)
	}
}

func TestReapReArmsTheExhaustionNotification(t *testing.T) {
	clock := time.Now()
	var calls int
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{
		SeriesBudget:      1,
		Now:               func() time.Time { return clock },
		OnBudgetExhausted: func(int) { calls++ },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	fill := func(workload string) {
		meta := enriched()
		meta.WorkloadName = workload
		_ = sink.Export(context.Background(), []*events.Event{{
			Type: events.EventDNS, LatencyNS: 1_000_000, K8s: meta,
		}})
	}

	fill("a")
	fill("b")
	if calls != 1 {
		t.Fatalf("notified %d times, want 1", calls)
	}

	clock = clock.Add(20 * time.Minute)
	sink.Reap(15 * time.Minute)

	fill("c")
	fill("d")
	if calls != 2 {
		t.Errorf("notified %d times, want 2; refilling the budget after a reap must "+
			"report again rather than staying silent forever", calls)
	}
}

func TestReapIsANoOpForNonPositiveTTL(t *testing.T) {
	sink, _ := newTestSink(t, 10)
	_ = sink.Export(context.Background(), []*events.Event{{
		Type: events.EventDNS, LatencyNS: 1000, K8s: enriched(),
	}})
	if n := sink.Reap(0); n != 0 {
		t.Errorf("Reap(0) removed %d series; a disabled TTL must never evict", n)
	}
}

func TestEvictionWorksWithTheBudgetDisabled(t *testing.T) {
	clock := time.Now()
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{
		SeriesBudget: 0,
		Now:          func() time.Time { return clock },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, workload := range []string{"a", "b", "c"} {
		meta := enriched()
		meta.WorkloadName = workload
		if err := sink.Export(context.Background(), []*events.Event{{
			Type: events.EventDNS, LatencyNS: 1_000_000, K8s: meta,
		}}); err != nil {
			t.Fatalf("Export: %v", err)
		}
	}
	if got := len(gather(t, reg, "podtrace_workload_dns_latency_seconds")); got != 3 {
		t.Fatalf("want 3 series with the cap lifted, got %d", got)
	}

	clock = clock.Add(20 * time.Minute)
	if n := sink.Reap(15 * time.Minute); n != 3 {
		t.Errorf("reaped %d with the budget disabled, want 3; lifting the cap must "+
			"not also disable eviction, or every series ever produced leaks", n)
	}
	if got := len(gather(t, reg, "podtrace_workload_dns_latency_seconds")); got != 0 {
		t.Errorf("%d series survived eviction", got)
	}
}

func TestEvictionRemovesCounterSeriesToo(t *testing.T) {
	clock := time.Now()
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := sink.Export(context.Background(), []*events.Event{{
		Type:      events.EventTCPSend,
		LatencyNS: 1_000_000,
		Bytes:     2048,
		K8s:       enriched(),
	}}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if got := len(gather(t, reg, "podtrace_workload_network_bytes_total")); got != 1 {
		t.Fatalf("want 1 counter series, got %d", got)
	}

	clock = clock.Add(20 * time.Minute)
	sink.Reap(15 * time.Minute)

	if got := len(gather(t, reg, "podtrace_workload_network_bytes_total")); got != 0 {
		t.Errorf("counter series survived eviction (%d); counters back the two "+
			"families that matter most, so leaking them is the worst case", got)
	}
	if got := len(gather(t, reg, "podtrace_workload_network_latency_seconds")); got != 0 {
		t.Errorf("histogram series from the same event survived (%d)", got)
	}
}

func TestDeleteSeriesReportsFalseForAnUnknownFamily(t *testing.T) {
	sink, _ := newTestSink(t, 0)

	if sink.deleteSeries(&seriesEntry{family: "not_a_family", labels: []string{"x"}}) {
		t.Error("deleteSeries claimed to remove a series from a family it cannot resolve")
	}
}
