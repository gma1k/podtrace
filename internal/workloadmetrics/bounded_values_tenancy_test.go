package workloadmetrics

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gma1k/podtrace/internal/events"
)

func enrichedIn(namespace string) *events.K8sMetadata {
	meta := enriched()
	meta.Namespace = namespace
	return meta
}

func grpcCall(namespace, method string) *events.Event {
	return &events.Event{
		Type:      events.EventGRPCMethod,
		LatencyNS: 1_000_000,
		Target:    method,
		K8s:       enrichedIn(namespace),
	}
}

func rpcMethodsIn(t *testing.T, reg *prometheus.Registry, namespace string) map[string]bool {
	t.Helper()
	methods := map[string]bool{}
	for _, m := range gather(t, reg, semconvRPCDuration) {
		if labels := labelsOf(m); labels["k8s_namespace_name"] == namespace {
			methods[labels["rpc_method"]] = true
		}
	}
	return methods
}

func export(t *testing.T, sink *Sink, batch ...*events.Event) {
	t.Helper()
	if err := sink.Export(context.Background(), batch); err != nil {
		t.Fatalf("Export: %v", err)
	}
}

func TestOneNamespacesMethodChurnDoesNotFoldAnothersRPCMethods(t *testing.T) {
	sink, reg := newSemconvSink(t, 3)
	for i := 0; i < 20; i++ {
		export(t, sink, grpcCall("scanner", fmt.Sprintf("/svc/Probe%d", i)))
	}
	export(t, sink, grpcCall("shop", "/shop.Cart/Checkout"))

	if got := rpcMethodsIn(t, reg, "shop"); !got["/shop.Cart/Checkout"] {
		t.Errorf("shop's rpc_method values = %v; another namespace's 20 methods folded it into %q",
			got, boundedValuesPlaceholder)
	}
	if got := rpcMethodsIn(t, reg, "scanner"); !got[boundedValuesPlaceholder] || len(got) > 4 {
		t.Errorf("scanner's rpc_method values = %v, want its own 3 plus the placeholder", got)
	}
}

func TestAReapedMethodGivesItsSlotBack(t *testing.T) {
	sink, reg := newSemconvSink(t, 1)
	clock := time.Unix(1000, 0)
	sink.now = func() time.Time { return clock }

	export(t, sink, grpcCall("shop", "/old.Service/Gone"))
	clock = clock.Add(time.Hour)
	sink.Reap(30 * time.Minute)
	export(t, sink, grpcCall("shop", "/new.Service/Live"))

	if got := rpcMethodsIn(t, reg, "shop"); !got["/new.Service/Live"] {
		t.Errorf("rpc_method values after the old method was reaped = %v; its slot was never freed", got)
	}
}

func TestOneNamespacesPeersDoNotFoldAnothersEdgeTargets(t *testing.T) {
	reg := prometheus.NewRegistry()
	var counter int
	sink, err := New(reg, Options{
		AttributeCardinality: 2,
		ResolvePeer: func(ip string, _ uint16) (PeerIdentity, bool) {
			if ip == "10.0.0.1" {
				return PeerIdentity{Service: "payments", Namespace: "shop"}, true
			}
			counter++
			return PeerIdentity{Service: fmt.Sprintf("svc-%d", counter), Namespace: "elsewhere"}, true
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 20; i++ {
		e := l7Event("10.9.9.9")
		e.K8s = enrichedIn("crawler")
		export(t, sink, e)
	}
	export(t, sink, l7Event("10.0.0.1"))

	var found bool
	for _, m := range gather(t, reg, metricPrefix+edgeRequestsTotal) {
		labels := labelsOf(m)
		if labels["namespace"] != "shop" {
			continue
		}
		found = true
		if labels["target_service"] != "payments" || labels["target_namespace"] != "shop" {
			t.Errorf("shop's edge = %v; another namespace's peers folded its target", labels)
		}
	}
	if !found {
		t.Error("shop produced no edge")
	}
}

func TestBoundedValuesKeepASetPerNamespace(t *testing.T) {
	b := newBoundedValues(2)
	now := time.Unix(1000, 0)
	b.bound("noisy", "a", now)
	b.bound("noisy", "b", now)
	if got := b.bound("noisy", "c", now); got != boundedValuesPlaceholder {
		t.Errorf("noisy overflow = %q, want %q", got, boundedValuesPlaceholder)
	}
	if got := b.bound("shop", "real", now); got != "real" {
		t.Errorf("another namespace's value = %q; one tenant's churn folded it into the placeholder", got)
	}
}

func TestBoundedValuesReapFreesIdleSlots(t *testing.T) {
	b := newBoundedValues(1)
	start := time.Unix(1000, 0)
	b.bound("shop", "old", start)
	if got := b.bound("shop", "new", start.Add(time.Minute)); got != boundedValuesPlaceholder {
		t.Fatalf("second value = %q before reaping, want %q", got, boundedValuesPlaceholder)
	}
	b.reap(start.Add(time.Minute))
	if got := b.bound("shop", "new", start.Add(2*time.Minute)); got != "new" {
		t.Errorf("after reaping the idle value, new = %q; a departed value held its slot forever", got)
	}
	if _, ok := b.seen["shop"]["old"]; ok {
		t.Error("the idle value survived the reap")
	}
}

func TestBoundedValuesReapKeepsRecentlySeenValues(t *testing.T) {
	b := newBoundedValues(1)
	start := time.Unix(1000, 0)
	b.bound("shop", "live", start)
	b.bound("shop", "live", start.Add(10*time.Minute))
	b.reap(start.Add(5 * time.Minute))
	if got := b.bound("shop", "other", start.Add(11*time.Minute)); got != boundedValuesPlaceholder {
		t.Errorf("a value refreshed after the cutoff lost its slot; other = %q", got)
	}
}

func TestBoundedValuesReapDropsEmptyNamespaces(t *testing.T) {
	b := newBoundedValues(3)
	start := time.Unix(1000, 0)
	b.bound("gone", "x", start)
	b.reap(start.Add(time.Second))
	if len(b.seen) != 0 {
		t.Errorf("namespaces kept after their last value was reaped: %v", b.seen)
	}
}

func TestReapingADisabledSetIsSafe(t *testing.T) {
	var b *boundedValues
	b.reap(time.Now())
}
