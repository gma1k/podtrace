package kubernetes

import (
	"context"
	"sync/atomic"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/gma1k/podtrace/internal/events"
)

func TestEnrichNetworkTarget_ExternalIPSkipsResolversAndCache(t *testing.T) {
	cs := fake.NewSimpleClientset()
	var apiCalls int32
	cs.PrependReactor("*", "*", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if v := a.GetVerb(); v == "list" || v == "get" {
			atomic.AddInt32(&apiCalls, 1)
		}
		return false, nil, nil
	})

	ce := NewContextEnricher(cs, &PodInfo{Namespace: "src"})
	ev := &events.Event{Type: events.EventConnect, Target: "8.8.8.8:53"}
	enriched := ce.EnrichEvent(context.Background(), ev)

	if enriched == nil || !enriched.KubernetesContext.IsExternal {
		t.Fatalf("external IP must be flagged external, got %+v", enriched)
	}
	if n := atomic.LoadInt32(&apiCalls); n != 0 {
		t.Fatalf("external IP must not trigger any API list/get, got %d", n)
	}
	populated := false
	ce.podCache.Range(func(any, any) bool { populated = true; return false })
	if populated {
		t.Fatal("external IP must not leave an entry in the pod cache")
	}
}

func TestResolveService_InformerEnabledSkipsClusterList(t *testing.T) {
	cs := fake.NewSimpleClientset()
	var lists int32
	cs.PrependReactor("list", "endpoints", func(k8stesting.Action) (bool, runtime.Object, error) {
		atomic.AddInt32(&lists, 1)
		return false, nil, nil
	})

	ic := NewInformerCache(cs)
	sr := NewServiceResolverWithCache(cs, ic)
	sr.ResolveService(context.Background(), "10.1.2.3", 8080)

	if n := atomic.LoadInt32(&lists); n != 0 {
		t.Fatalf("with informers enabled, an endpoint miss must not fall back to a cluster-wide Endpoints LIST, got %d", n)
	}
}
