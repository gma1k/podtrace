package workloadmetrics

import (
	"context"
	"fmt"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/events"
)

func staticPeer(service, namespace string) func(string, uint16) (PeerIdentity, bool) {
	return func(ip string, _ uint16) (PeerIdentity, bool) {
		if ip == "" {
			return PeerIdentity{}, false
		}
		return PeerIdentity{Service: service, Namespace: namespace}, true
	}
}

func newEdgeSink(t *testing.T, resolve func(string, uint16) (PeerIdentity, bool)) (*Sink, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{ResolvePeer: resolve})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return sink, reg
}

func l7Event(peer string) *events.Event {
	return &events.Event{
		Type:        events.EventHTTPResp,
		LatencyNS:   3_000_000,
		Details:     "200",
		PeerDstIP:   peer,
		PeerDstPort: 8080,
		K8s:         enriched(),
	}
}

func TestAnL7CallProducesAnEdge(t *testing.T) {
	sink, reg := newEdgeSink(t, staticPeer("payments", "shop"))

	if err := sink.Export(context.Background(), []*events.Event{l7Event("10.244.1.7")}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	series := gather(t, reg, metricPrefix+edgeRequestsTotal)
	if len(series) != 1 {
		t.Fatalf("want 1 edge series, got %d", len(series))
	}
	got := labelsOf(series[0])
	for key, want := range map[string]string{
		"namespace":        "shop",
		"workload":         "checkout",
		"target_namespace": "shop",
		"target_service":   "payments",
		"outcome":          "ok",
	} {
		if got[key] != want {
			t.Errorf("label %q = %q, want %q", key, got[key], want)
		}
	}
}

func TestTheEdgeCarriesRedNotJustTheEdge(t *testing.T) {
	sink, reg := newEdgeSink(t, staticPeer("payments", "shop"))

	ok := l7Event("10.244.1.7")
	bad := l7Event("10.244.1.7")
	bad.Details = "503"
	bad.Error = 503
	if err := sink.Export(context.Background(), []*events.Event{ok, bad}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	outcomes := map[string]bool{}
	for _, m := range gather(t, reg, metricPrefix+edgeRequestsTotal) {
		outcomes[labelsOf(m)["outcome"]] = true
	}
	if !outcomes["ok"] || !outcomes["error"] {
		t.Errorf("outcomes seen = %v; the map is only useful if an edge shows how badly it is "+
			"going, not just that it exists", outcomes)
	}

	if len(gather(t, reg, metricPrefix+edgeRequestDuration)) == 0 {
		t.Error("no edge duration histogram; RED per edge needs the D")
	}
}

func TestNonL7TrafficProducesAnEdge(t *testing.T) {
	sink, reg := newEdgeSink(t, staticPeer("postgres", "data"))

	if err := sink.Export(context.Background(), []*events.Event{{
		Type: events.EventTCPSend, Bytes: 4096, LatencyNS: 500_000,
		PeerDstIP: "10.244.2.9", PeerDstPort: 5432, K8s: enriched(),
	}}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	series := gather(t, reg, metricPrefix+edgeBytesTotal)
	if len(series) != 1 {
		t.Fatalf("want 1 byte-edge series, got %d. A database or a cache carries no L7 payload "+
			"podtrace can decode, and a map that omits them is not a map of the system",
			len(series))
	}
	got := labelsOf(series[0])
	if got["target_service"] != "postgres" || got["direction"] != "egress" {
		t.Errorf("labels = %v, want postgres/egress", got)
	}
}

func TestAZeroByteTransferProducesNoByteEdge(t *testing.T) {
	sink, reg := newEdgeSink(t, staticPeer("postgres", "data"))

	if err := sink.Export(context.Background(), []*events.Event{{
		Type: events.EventTCPSend, Bytes: 0, LatencyNS: 1_000,
		PeerDstIP: "10.244.2.9", PeerDstPort: 5432, K8s: enriched(),
	}}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if series := gather(t, reg, metricPrefix+edgeBytesTotal); len(series) != 0 {
		t.Errorf("got %d byte-edge series for a zero-byte transfer", len(series))
	}
}

func TestAnEventWithNoPeerProducesNoEdge(t *testing.T) {
	sink, reg := newEdgeSink(t, staticPeer("payments", "shop"))

	if err := sink.Export(context.Background(), []*events.Event{l7Event("")}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if series := gather(t, reg, metricPrefix+edgeRequestsTotal); len(series) != 0 {
		t.Errorf("got %d edge series for an event with no peer", len(series))
	}
}

func TestTheEdgeFamiliesAreAbsentWithoutAResolver(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := sink.Export(context.Background(), []*events.Event{l7Event("10.244.1.7")}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() == metricPrefix+edgeRequestsTotal {
			t.Error("the topology families were registered with no way to resolve a peer. An " +
				"agent that cannot watch EndpointSlices would expose families that stay empty " +
				"forever, which reads as a broken feature rather than an absent one")
		}
	}
}

func TestTheNearEndIsNeverTheFarEnd(t *testing.T) {
	sink, reg := newEdgeSink(t, staticPeer("payments", "shop"))

	if err := sink.Export(context.Background(), []*events.Event{l7Event("10.244.1.7")}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	got := labelsOf(gather(t, reg, metricPrefix+edgeRequestsTotal)[0])
	if got["workload"] == got["target_service"] {
		t.Error("the near and far ends carry the same value; an edge from a node to itself " +
			"draws nothing")
	}
}

func TestTheFarEndIsBounded(t *testing.T) {
	reg := prometheus.NewRegistry()
	var counter int
	sink, err := New(reg, Options{
		AttributeCardinality: 5,
		ResolvePeer: func(string, uint16) (PeerIdentity, bool) {
			counter++
			return PeerIdentity{Service: fmt.Sprintf("svc-%d", counter), Namespace: "shop"}, true
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := 0; i < 200; i++ {
		if err := sink.Export(context.Background(), []*events.Event{l7Event("10.244.1.7")}); err != nil {
			t.Fatalf("Export: %v", err)
		}
	}

	targets := map[string]bool{}
	for _, m := range gather(t, reg, metricPrefix+edgeRequestsTotal) {
		targets[labelsOf(m)["target_service"]] = true
	}
	if len(targets) > 6 {
		t.Errorf("200 distinct peers produced %d target values with a limit of 5. A Service "+
			"name is closed, but external traffic is not: without a ceiling a workload talking "+
			"to many destinations mints an edge per destination", len(targets))
	}
	if !targets[boundedValuesPlaceholder] {
		t.Errorf("the tail did not fold into %q; targets = %v", boundedValuesPlaceholder, targets)
	}
}

func TestAFoldedTargetReportsNoNamespace(t *testing.T) {
	reg := prometheus.NewRegistry()
	var counter int
	sink, err := New(reg, Options{
		AttributeCardinality: 1,
		ResolvePeer: func(string, uint16) (PeerIdentity, bool) {
			counter++
			return PeerIdentity{Service: fmt.Sprintf("svc-%d", counter), Namespace: "shop"}, true
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 10; i++ {
		if err := sink.Export(context.Background(), []*events.Event{l7Event("10.244.1.7")}); err != nil {
			t.Fatalf("Export: %v", err)
		}
	}

	for _, m := range gather(t, reg, metricPrefix+edgeRequestsTotal) {
		got := labelsOf(m)
		if got["target_service"] == boundedValuesPlaceholder && got["target_namespace"] != "unknown" {
			t.Errorf("a folded target reported namespace %q; carrying the real one implies a "+
				"precision the label no longer has", got["target_namespace"])
		}
	}
}

func TestAPlaceholderPeerReportsNoNamespace(t *testing.T) {
	sink, reg := newEdgeSink(t, func(string, uint16) (PeerIdentity, bool) {
		return PeerIdentity{Service: "external"}, true
	})

	if err := sink.Export(context.Background(), []*events.Event{l7Event("93.184.6.34")}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	got := labelsOf(gather(t, reg, metricPrefix+edgeRequestsTotal)[0])
	if got["target_service"] != "external" {
		t.Fatalf("target_service = %q, want external", got["target_service"])
	}
	if got["target_namespace"] != "unknown" {
		t.Errorf("target_namespace = %q, want unknown; traffic leaving the cluster has no "+
			"namespace", got["target_namespace"])
	}
}

func TestEdgeSeriesCountTheBudgetTheSameWayEveryOtherFamilyDoes(t *testing.T) {
	reg := prometheus.NewRegistry()
	sink, err := New(reg, Options{SeriesBudget: 1, ResolvePeer: staticPeer("payments", "shop")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := 0; i < 20; i++ {
		e := l7Event("10.244.1.7")
		e.K8s.WorkloadName = fmt.Sprintf("workload-%d", i)
		if err := sink.Export(context.Background(), []*events.Event{e}); err != nil {
			t.Fatalf("Export: %v", err)
		}
	}

	dropped := gather(t, reg, "podtrace_workload_metrics_series_dropped_total")
	if len(dropped) == 0 {
		t.Error("the edge families minted series past an exhausted budget without being " +
			"counted. A documented cap that one family ignores is not a cap")
	}
}

func TestTheEdgeSurfaceIsDeliberatelyCoarse(t *testing.T) {
	for _, collector := range newEdgeCollectors(false, 10).all() {
		for _, label := range collectorLabelNames(t, collector) {
			switch label {
			case "container", "protocol", "status_class", "pod", "process":
				t.Errorf("the edge families carry %q. Those questions are answered by the "+
					"per-workload families; multiplying them by peer count is what makes "+
					"topology expensive", label)
			}
		}
	}
}

func TestAnUnattributedEventProducesNoEdge(t *testing.T) {
	sink, reg := newEdgeSink(t, staticPeer("payments", "shop"))

	orphan := l7Event("10.244.1.7")
	orphan.K8s = nil
	if err := sink.Export(context.Background(), []*events.Event{orphan}); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if series := gather(t, reg, metricPrefix+edgeRequestsTotal); len(series) != 0 {
		t.Errorf("got %d edge series for an event with no workload; an edge needs both ends",
			len(series))
	}
}

func TestDuplicateEdgeFamilyRegistrationIsReported(t *testing.T) {
	reg := prometheus.NewRegistry()
	if err := newEdgeCollectors(false, 10).register(reg); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	if err := newEdgeCollectors(false, 10).register(reg); err == nil {
		t.Error("registering the topology families twice was accepted; a silent collision " +
			"would leave one set of collectors receiving observations nobody scrapes")
	}
}

func TestSinkReportsAnEdgeRegistrationCollision(t *testing.T) {
	reg := prometheus.NewRegistry()
	if err := newEdgeCollectors(false, 10).register(reg); err != nil {
		t.Fatalf("seed registration: %v", err)
	}
	if _, err := New(reg, Options{ResolvePeer: staticPeer("payments", "shop")}); err == nil {
		t.Error("New accepted a registry that already holds the topology families")
	}
}

func TestEdgeIdentityRefusesAnEventItCannotAttribute(t *testing.T) {
	sink, _ := newEdgeSink(t, staticPeer("payments", "shop"))

	if _, ok := sink.edgeIdentity(&events.Event{PeerDstIP: "10.244.1.7"}); ok {
		t.Error("an event with no resolvable workload produced an edge identity. Export bails " +
			"earlier today, but the guard is what keeps that true if the near end is ever " +
			"resolved lazily")
	}
}
