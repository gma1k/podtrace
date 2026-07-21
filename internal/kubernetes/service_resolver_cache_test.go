package kubernetes

import (
	"context"
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestNewServiceResolverWithCache_ClampsNegativeTTL(t *testing.T) {
	t.Setenv("PODTRACE_K8S_CACHE_TTL", "10")
	sr := NewServiceResolverWithCache(fake.NewSimpleClientset(), nil)
	if sr.cacheTTL != 10*time.Second {
		t.Fatalf("expected cacheTTL=10s, got %v", sr.cacheTTL)
	}
	if sr.negativeTTL != sr.cacheTTL {
		t.Errorf("expected negativeTTL clamped to cacheTTL (%v), got %v", sr.cacheTTL, sr.negativeTTL)
	}
}

func TestResolveService_NilClientsetInformerFallback(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	ic := NewInformerCache(clientset)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ic.Start(ctx)
	defer ic.Stop()

	ic.mu.RLock()
	esInf := ic.esInf
	ic.mu.RUnlock()
	if esInf == nil {
		t.Skip("endpointslice informer not initialized")
	}
	port := int32(9090)
	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Name: "svc-abc", Namespace: "default", Labels: map[string]string{serviceNameKey: "cache-svc"}},
		Ports:      []discoveryv1.EndpointPort{{Port: &port}},
		Endpoints:  []discoveryv1.Endpoint{{Addresses: []string{"10.3.3.3"}}},
	}
	if err := esInf.GetIndexer().Add(es); err != nil {
		t.Fatalf("add endpointslice: %v", err)
	}

	sr := NewServiceResolverWithCache(nil, ic)
	svc := sr.ResolveService(ctx, "10.3.3.3", 9090)
	if svc == nil || svc.Name != "cache-svc" {
		t.Errorf("expected cache-svc via informer fallback, got %+v", svc)
	}
}

func TestFetchServiceByEndpoint_ListError(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	clientset.PrependReactor("list", "endpoints", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("synthetic endpoints list failure")
	})
	sr := NewServiceResolver(clientset)
	if svc := sr.fetchServiceByEndpoint(context.Background(), "10.1.1.1", 80); svc != nil {
		t.Errorf("expected nil on endpoints list error, got %+v", svc)
	}
}

var _ runtime.Object = &corev1.Endpoints{} //nolint:staticcheck // Endpoints API still widely used
