package kubernetes

import (
	"context"
	"testing"
	"time"

	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestGetServiceByEndpoint_UnknownEndpointReturnsNil(t *testing.T) {
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

	if svc := ic.GetServiceByEndpoint("10.99.99.99", 8080); svc != nil {
		t.Errorf("expected nil for an endpoint not present in the index, got %+v", svc)
	}
}

func TestGetServiceByEndpoint_WhitespaceServiceNameReturnsNil(t *testing.T) {
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

	port := int32(9000)
	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "blank-name", Labels: map[string]string{serviceNameKey: "   "}},
		Ports:      []discoveryv1.EndpointPort{{Port: &port}},
		Endpoints:  []discoveryv1.Endpoint{{Addresses: []string{"10.3.3.3"}}},
	}
	if err := esInf.GetIndexer().Add(es); err != nil {
		t.Fatalf("add endpointslice: %v", err)
	}

	if svc := ic.GetServiceByEndpoint("10.3.3.3", 9000); svc != nil {
		t.Errorf("expected nil when the service-name label is only whitespace, got %+v", svc)
	}
}
