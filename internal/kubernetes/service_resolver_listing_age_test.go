package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func countEndpointLists(cs *fake.Clientset, fail bool) *int32 {
	var lists int32
	cs.PrependReactor("list", "endpoints", func(k8stesting.Action) (bool, runtime.Object, error) {
		atomic.AddInt32(&lists, 1)
		if fail {
			return true, nil, errors.New("forbidden")
		}
		return true, &corev1.EndpointsList{Items: []endpointsObject{endpointsFor("shop", "api", "10.0.0.1", 80)}}, nil
	})
	return &lists
}

func TestABurstOfUnknownPeersCostsOneEndpointListing(t *testing.T) {
	cs := fake.NewClientset()
	lists := countEndpointLists(cs, false)
	sr := NewServiceResolver(cs)
	for i := 0; i < 50; i++ {
		if svc := sr.ResolveService(context.Background(), fmt.Sprintf("10.1.0.%d", i), 8080); svc != nil {
			t.Fatalf("peer %d resolved to %+v, want a miss", i, svc)
		}
	}
	if svc := sr.ResolveService(context.Background(), "10.0.0.1", 80); svc == nil || svc.Name != "api" {
		t.Fatalf("known endpoint resolved to %+v", svc)
	}
	if n := atomic.LoadInt32(lists); n != 1 {
		t.Fatalf("listings = %d, want 1 for 51 lookups", n)
	}
}

func TestAnUnknownPeerRefreshesAListingOlderThanTheNegativeTTL(t *testing.T) {
	cs := fake.NewClientset()
	lists := countEndpointLists(cs, false)
	sr := NewServiceResolver(cs)
	sr.ResolveService(context.Background(), "10.1.0.1", 8080)

	sr.mu.Lock()
	sr.listedAt = time.Now().Add(-sr.negativeTTL - time.Second)
	sr.mu.Unlock()
	sr.ResolveService(context.Background(), "10.1.0.2", 8080)
	if n := atomic.LoadInt32(lists); n != 2 {
		t.Fatalf("listings = %d, want a refresh once the listing is older than the negative TTL", n)
	}
}

func TestAFailedListingHoldsOffTheNextAttempt(t *testing.T) {
	cs := fake.NewClientset()
	lists := countEndpointLists(cs, true)
	sr := NewServiceResolver(cs)
	for i := 0; i < 20; i++ {
		sr.ResolveService(context.Background(), fmt.Sprintf("10.1.0.%d", i), 8080)
	}
	if n := atomic.LoadInt32(lists); n != 1 {
		t.Fatalf("listings = %d, want 1 failing attempt per negative TTL", n)
	}
	sr.mu.RLock()
	defer sr.mu.RUnlock()
	if !sr.listFailed {
		t.Fatal("the failed attempt must be recorded")
	}
}
