package workloadmetrics

import (
	"fmt"
	"sort"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/gma1k/podtrace/internal/ebpf/kernelagg"
	"github.com/gma1k/podtrace/internal/events"
)

const kernelTestCgroup = uint64(4242)

func kernelTestLookup(uint64) (events.K8sMetadata, bool) {
	return events.K8sMetadata{
		Namespace:     "shop",
		WorkloadName:  "checkout",
		WorkloadKind:  "Deployment",
		ContainerName: "app",
	}, true
}

func kernelSink(t *testing.T) (*Sink, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{
		NativeHistograms:  true,
		KernelAggregation: true,
		Lookup:            kernelTestLookup,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return sink, reg
}

func eventSink(t *testing.T) (*Sink, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{
		NativeHistograms: true,
		Lookup:           kernelTestLookup,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return sink, reg
}

func seriesIdentities(t *testing.T, reg *prometheus.Registry) []string {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	var out []string
	for _, f := range families {
		for _, m := range f.GetMetric() {
			id := f.GetName()
			for _, l := range m.GetLabel() {
				id += "|" + l.GetName() + "=" + l.GetValue()
			}
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func kernelRow(eventType events.EventType, variant uint8, bucket uint16, count, sumNS, bytes uint64) kernelagg.Row {
	return kernelagg.Row{
		Key: kernelagg.Key{
			CgroupID:  kernelTestCgroup,
			EventType: uint8(eventType),
			Variant:   variant,
			Bucket:    bucket,
		},
		Value: kernelagg.Value{Count: count, SumNS: sumNS, Bytes: bytes},
	}
}

func TestKernelAndEventPathsProduceTheSameSeries(t *testing.T) {
	eventSink, eventReg := eventSink(t)
	kernSink, kernReg := kernelSink(t)

	eventSink.record(&events.Event{
		Type: events.EventTCPSend, CgroupID: kernelTestCgroup,
		LatencyNS: 250_000, Bytes: 1500,
	}, []string{"shop", "checkout", "Deployment", "app"})

	kernSink.IngestKernel([]kernelagg.Row{
		kernelRow(events.EventTCPSend, 0, kernelagg.BucketIndex(250_000), 1, 250_000, 1500),
	})

	got, want := seriesIdentities(t, kernReg), seriesIdentities(t, eventReg)
	if len(got) != len(want) {
		t.Fatalf("kernel path produced %d series, event path %d\nkernel: %v\nevent:  %v",
			len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("series %d differs:\n  kernel: %s\n  event:  %s\nA dashboard must not be able "+
				"to tell which path served it", i, got[i], want[i])
		}
	}
}

func TestKernelHistogramCarriesCountAndSum(t *testing.T) {
	sink, reg := kernelSink(t)

	sink.IngestKernel([]kernelagg.Row{
		kernelRow(events.EventDNS, 0, 100, 3, 30_000_000, 0),
		kernelRow(events.EventDNS, 0, 120, 2, 40_000_000, 0),
	})

	metrics := gather(t, reg, "podtrace_workload_dns_latency_seconds")
	if len(metrics) != 1 {
		t.Fatalf("got %d series, want 1", len(metrics))
	}
	h := metrics[0].GetHistogram()
	if h.GetSampleCount() != 5 {
		t.Errorf("count = %d, want 5 (3+2 observations folded from two buckets)", h.GetSampleCount())
	}
	if got := h.GetSampleSum(); got < 0.069 || got > 0.071 {
		t.Errorf("sum = %v, want ~0.07s", got)
	}
	if h.GetSchema() != kernelagg.Schema {
		t.Errorf("schema = %d, want %d; the kernel's indices are only meaningful at the "+
			"schema they were computed in", h.GetSchema(), kernelagg.Schema)
	}
}

func TestKernelBytesFeedTheSameCounterAsEvents(t *testing.T) {
	sink, reg := kernelSink(t)

	sink.IngestKernel([]kernelagg.Row{
		kernelRow(events.EventTCPSend, 0, 80, 4, 1_000_000, 6000),
	})

	metrics := gather(t, reg, "podtrace_workload_network_bytes_total")
	if len(metrics) != 1 {
		t.Fatalf("got %d series, want 1", len(metrics))
	}
	if got := metrics[0].GetCounter().GetValue(); got != 6000 {
		t.Errorf("bytes = %v, want 6000; a drained delta is an Add, so the kernel path must "+
			"reuse the counter the event path already owns", got)
	}
}

func TestAnUnattributableRowIsDropped(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{
		NativeHistograms:  true,
		KernelAggregation: true,
		Lookup:            func(uint64) (events.K8sMetadata, bool) { return events.K8sMetadata{}, false },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if applied := sink.IngestKernel([]kernelagg.Row{
		kernelRow(events.EventTCPSend, 0, 80, 1, 1000, 100),
	}); applied != 0 {
		t.Errorf("applied = %d, want 0. A cgroup that is no longer resident has no workload "+
			"to label, and guessing would attribute traffic to the wrong pod", applied)
	}
}

func TestKernelHistogramsRetireWithTheirWorkload(t *testing.T) {
	sink, _ := kernelSink(t)
	sink.IngestKernel([]kernelagg.Row{kernelRow(events.EventDNS, 0, 100, 1, 1000, 0)})

	if removed := sink.kernelHist.reap(0); removed == 0 {
		t.Error("no series retired; a departed pod would keep reporting its last distribution " +
			"forever, and the series budget would never recover")
	}
	var collected []prometheus.Metric
	ch := make(chan prometheus.Metric, 8)
	sink.kernelHist.Collect(ch)
	close(ch)
	for m := range ch {
		collected = append(collected, m)
	}
	if len(collected) != 0 {
		t.Errorf("collected %d series after retirement, want 0", len(collected))
	}
}

var _ = dto.Metric{}

func kernelEdgeSink(t *testing.T) (*Sink, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{
		NativeHistograms:  true,
		KernelAggregation: true,
		Lookup:            kernelTestLookup,
		ResolvePeer: func(ip string, port uint16) (PeerIdentity, bool) {
			if ip == "10.244.1.7" && port == 8080 {
				return PeerIdentity{Service: "payments", Namespace: "shop"}, true
			}
			return PeerIdentity{}, false
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return sink, reg
}

func kernelPeerRow(eventType events.EventType, variant uint8, bucket uint16, count, sumNS, bytes uint64) kernelagg.Row {
	row := kernelRow(eventType, variant, bucket, count, sumNS, bytes)
	row.Key.PeerIP = 0x0AF40107
	row.Key.PeerPort = 8080
	return row
}

func TestTheServiceMapSurvivesKernelAggregation(t *testing.T) {
	sink, reg := kernelEdgeSink(t)

	sink.IngestKernel([]kernelagg.Row{
		kernelPeerRow(events.EventTCPSend, 0, kernelagg.BucketIndex(200_000), 5, 1_000_000, 7500),
		kernelPeerRow(events.EventHTTPResp, 1<<3|2<<3, kernelagg.BucketIndex(3_000_000), 3, 9_000_000, 0),
	})

	for _, family := range []string{
		"podtrace_workload_edge_bytes_total",
		"podtrace_workload_edge_requests_total",
		"podtrace_workload_edge_request_duration_seconds",
	} {
		metrics := gather(t, reg, family)
		if len(metrics) == 0 {
			t.Errorf("%s is empty. Bypassing the ringbuf removes the events edges were derived "+
				"from, so the kernel path must feed the map or the topology goes dark on exactly "+
				"the nodes the bypass is meant to help", family)
			continue
		}
		var target string
		for _, l := range metrics[0].GetLabel() {
			if l.GetName() == "target_service" {
				target = l.GetValue()
			}
		}
		if target != "payments" {
			t.Errorf("%s target_service = %q, want payments; the peer address must resolve "+
				"through the same join the event path uses", family, target)
		}
	}
}

func TestKernelEdgeDurationIsNotAlsoObservedByTheEventPath(t *testing.T) {
	sink, _ := kernelEdgeSink(t)

	if !sink.kernelHist.owns(edgeRequestDuration) {
		t.Fatal("the kernel does not own the edge duration family, so the event path would " +
			"keep feeding it and every edge latency would be counted twice")
	}
	if sink.kernelHist.owns("edge_bytes_total") {
		t.Error("a counter must not be owned by the histogram collector; a drained delta is an Add")
	}
}

func TestEveryKernelFamilyLandsOnItsMetric(t *testing.T) {
	sink, reg := kernelSink(t)

	sink.IngestKernel([]kernelagg.Row{
		kernelRow(events.EventRead, 0, kernelagg.BucketIndex(500_000), 2, 1_000_000, 4096),
		kernelRow(events.EventWrite, 0, kernelagg.BucketIndex(600_000), 1, 600_000, 2048),
		kernelRow(events.EventFsync, 0, kernelagg.BucketIndex(700_000), 1, 700_000, 0),
		kernelRow(events.EventSchedSwitch, 0, kernelagg.BucketIndex(900_000), 3, 2_700_000, 0),
		kernelRow(events.EventTLSHandshake, 0, kernelagg.BucketIndex(4_000_000), 1, 4_000_000, 0),
	})

	for _, family := range []string{
		"podtrace_workload_filesystem_latency_seconds",
		"podtrace_workload_filesystem_bytes_total",
		"podtrace_workload_cpu_blocked_seconds",
		"podtrace_workload_tls_handshake_duration_seconds",
	} {
		if len(gather(t, reg, family)) == 0 {
			t.Errorf("%s is empty; a family the kernel records but the sink drops is invisible "+
				"with no error anywhere", family)
		}
	}
}

func TestAnErrorRowIncrementsTheErrorCounter(t *testing.T) {
	sink, reg := kernelSink(t)
	errorVariant := uint8(1 << 6)

	sink.IngestKernel([]kernelagg.Row{
		kernelRow(events.EventTCPSend, errorVariant, kernelagg.BucketIndex(1000), 7, 7000, 10),
	})

	metrics := gather(t, reg, "podtrace_workload_errors_total")
	if len(metrics) == 0 {
		t.Fatal("no errors_total series; the kernel packs an error flag into the variant and " +
			"it must reach the same counter the event path uses")
	}
	if got := metrics[0].GetCounter().GetValue(); got != 7 {
		t.Errorf("errors_total = %v, want 7 (the row's count, not one per row)", got)
	}
}

func TestAnUnknownEventTypeIsIgnored(t *testing.T) {
	sink, _ := kernelSink(t)
	if applied := sink.IngestKernel([]kernelagg.Row{
		kernelRow(events.EventPageFault, 0, 10, 1, 100, 0),
	}); applied != 0 {
		t.Errorf("applied = %d, want 0; this surface covers golden signals, not every event "+
			"podtrace can emit", applied)
	}
}

func TestStatusClassAndOutcomeCoverEveryPacking(t *testing.T) {
	for class, want := range map[uint8]string{1: "1xx", 2: "2xx", 3: "3xx", 4: "4xx", 5: "5xx", 0: "unknown", 7: "unknown"} {
		if got := kernelStatusClass(kernelagg.Variant{StatusClass: class}); got != want {
			t.Errorf("kernelStatusClass(%d) = %q, want %q", class, got, want)
		}
	}
	if got := kernelOutcome(kernelagg.Variant{IsError: true}); got != "error" {
		t.Errorf("outcome = %q, want error", got)
	}
	if got := kernelOutcome(kernelagg.Variant{}); got != "ok" {
		t.Errorf("outcome = %q, want ok", got)
	}
}

func TestCounterOnlyRowsSkipTheHistogram(t *testing.T) {
	sink, _ := kernelSink(t)
	row := kernelRow(events.EventTCPSend, 0, kernelagg.BucketNone, 3, 0, 900)
	sink.IngestKernel([]kernelagg.Row{row})

	ch := make(chan prometheus.Metric, 8)
	sink.kernelHist.Collect(ch)
	close(ch)
	for range ch {
		t.Fatal("a row marked BucketNone carries no latency observation, so it must not create " +
			"a histogram series with a meaningless bucket")
	}
}

func TestIngestIsSafeOnASinkWithoutKernelAggregation(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{Lookup: kernelTestLookup})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if applied := sink.IngestKernel([]kernelagg.Row{kernelRow(events.EventDNS, 0, 10, 1, 100, 0)}); applied != 0 {
		t.Errorf("applied = %d on a sink with aggregation off, want 0", applied)
	}
	if applied := (*Sink)(nil).IngestKernel(nil); applied != 0 {
		t.Errorf("a nil sink applied %d rows", applied)
	}
}

func TestEdgeProjectionSkipsWhatItCannotResolve(t *testing.T) {
	sink, reg := kernelEdgeSink(t)

	unknown := kernelRow(events.EventTCPSend, 0, kernelagg.BucketIndex(1000), 1, 1000, 500)
	unknown.Key.PeerIP = 0x08080808
	unknown.Key.PeerPort = 443
	sink.IngestKernel([]kernelagg.Row{unknown})

	for _, m := range gather(t, reg, "podtrace_workload_edge_bytes_total") {
		for _, l := range m.GetLabel() {
			if l.GetName() == "target_service" && l.GetValue() == "payments" {
				t.Error("an unresolved peer was drawn as payments; the resolver said no and the " +
					"edge must be dropped rather than attributed to the wrong service")
			}
		}
	}
}

func collectAll(k *kernelHistograms) []prometheus.Metric {
	ch := make(chan prometheus.Metric, 16)
	k.Collect(ch)
	close(ch)
	var out []prometheus.Metric
	for m := range ch {
		out = append(out, m)
	}
	return out
}

func TestObserveBucketIgnoresAFamilyItDoesNotOwn(t *testing.T) {
	k := newKernelHistograms([]string{"namespace"}, false)
	k.observeBucket("not_a_family", []string{"ns"}, 10, 1, 0.1)

	if got := len(collectAll(k)); got != 0 {
		t.Errorf("collected %d series for an unknown family, want 0. Silently creating one "+
			"would emit a metric no Desc describes and fail the scrape", got)
	}
}

func TestCollectSkipsSeriesThatCannotBeBuilt(t *testing.T) {
	k := newKernelHistograms([]string{"namespace"}, false)

	k.observeBucket("dns_latency_seconds", []string{"ns"}, 12, 0, 0)
	if got := len(collectAll(k)); got != 0 {
		t.Errorf("collected %d empty series, want 0", got)
	}

	k.observeBucket("dns_latency_seconds", []string{"ns", "extra"}, 12, 1, 0.1)
	if got := len(collectAll(k)); got != 0 {
		t.Errorf("collected %d series with a mismatched label count, want 0", got)
	}
}

func TestCollectSkipsAFamilyWithNoDescriptor(t *testing.T) {
	k := newKernelHistograms([]string{"namespace"}, false)
	k.series["orphan"] = map[string]*kernelHistogram{
		"x": {labelValues: []string{"ns"}, count: 1, buckets: map[int]int64{1: 1}},
	}

	if got := len(collectAll(k)); got != 0 {
		t.Errorf("collected %d series for a family with no Desc, want 0", got)
	}
}

func TestTheBudgetBoundsTheKernelPathToo(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{
		NativeHistograms:  true,
		KernelAggregation: true,
		SeriesBudget:      1,
		Lookup: func(cgroup uint64) (events.K8sMetadata, bool) {
			return events.K8sMetadata{
				Namespace:     "shop",
				WorkloadName:  fmt.Sprintf("checkout-%d", cgroup),
				WorkloadKind:  "Deployment",
				ContainerName: "app",
			}, true
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := 0; i < 12; i++ {
		row := kernelRow(events.EventDNS, 0, kernelagg.BucketIndex(1000), 1, 1000, 0)
		row.Key.CgroupID = uint64(1000 + i)
		sink.IngestKernel([]kernelagg.Row{row})
	}

	dropped := gather(t, reg, "podtrace_workload_metrics_series_dropped_total")
	if len(dropped) == 0 {
		t.Error("the kernel path admitted series past the budget without counting a drop; the " +
			"cap has to bound both paths or a node can exceed it by switching mode")
	}
}

func TestTheEventPathStopsObservingFamiliesTheKernelOwns(t *testing.T) {
	sink, reg := kernelSink(t)

	sink.record(&events.Event{
		Type: events.EventDNS, CgroupID: kernelTestCgroup, LatencyNS: 5_000_000,
	}, []string{"shop", "checkout", "Deployment", "app"})

	if got := len(gather(t, reg, "podtrace_workload_dns_latency_seconds")); got != 0 {
		t.Errorf("the event path produced %d dns series while the kernel owns the family; both "+
			"feeding it would double every latency distribution", got)
	}
}

func TestAKernelFamilyCollisionFailsAtStartup(t *testing.T) {
	reg := prometheus.NewRegistry()
	squatter := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: metricPrefix + "dns_latency_seconds",
		Help: "occupied",
	}, defaultBaseLabels)
	if err := reg.Register(squatter); err != nil {
		t.Fatalf("register squatter: %v", err)
	}

	if _, err := New(reg, Options{KernelAggregation: true, Lookup: kernelTestLookup}); err == nil {
		t.Error("a colliding kernel family reported success; the duplicate would fail every " +
			"scrape at runtime instead of failing loudly at startup")
	}
}

func TestKernelPathRecordsConnectionAcquireWaits(t *testing.T) {
	sink, reg := kernelSink(t)

	sink.IngestKernel([]kernelagg.Row{
		kernelRow(events.EventDBAcquire, 0, 140, 4, 480_000_000, 0),
	})

	metrics := gather(t, reg, "podtrace_workload_db_connection_acquire_seconds")
	if len(metrics) != 1 {
		t.Fatalf("got %d series, want 1; the kernel path must reach the same family as "+
			"the event path or the metric disappears wherever kernelAggregation is on",
			len(metrics))
	}
	h := metrics[0].GetHistogram()
	if h.GetSampleCount() != 4 {
		t.Errorf("count = %d, want 4", h.GetSampleCount())
	}
	if got := h.GetSampleSum(); got < 0.47 || got > 0.49 {
		t.Errorf("sum = %v, want ~0.48s", got)
	}
}

func TestEveryEventTypeReachesTheSameFamiliesOnBothPaths(t *testing.T) {
	familyNames := func(reg *prometheus.Registry) map[string]bool {
		t.Helper()
		families, err := reg.Gather()
		if err != nil {
			t.Fatalf("Gather: %v", err)
		}
		out := map[string]bool{}
		for _, f := range families {
			if len(f.GetMetric()) > 0 {
				out[f.GetName()] = true
			}
		}
		return out
	}

	for typ, name := range allEventTypes {
		eSink, eReg := eventSink(t)
		kSink, kReg := kernelSink(t)

		eSink.record(&events.Event{
			Type: typ, CgroupID: kernelTestCgroup, LatencyNS: 30_000_000, Bytes: 0,
		}, []string{"shop", "checkout", "Deployment", "app"})

		row := kernelRow(typ, 0, kernelagg.BucketIndex(30_000_000), 1, 30_000_000, 0)
		if !kSink.ingestKernelRow(&row) {
			continue
		}

		want, got := familyNames(eReg), familyNames(kReg)
		for family := range want {
			if !got[family] {
				t.Errorf("%s reaches %s on the event path but not on the kernel path.\n\n"+
					"A histogram family reaches kernelObserve only if kernelHistogramLabels "+
					"declares it; otherwise there is no descriptor, the observation is "+
					"dropped, and the switch arm still reports it handled the row. The "+
					"metric then exists in a default deployment and silently vanishes "+
					"wherever kernelAggregation is on.", name, family)
			}
		}
	}
}
