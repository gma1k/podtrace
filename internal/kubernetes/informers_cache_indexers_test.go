package kubernetes

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestInformerCache_IndexersAndLookups_Deterministic(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	ic := NewInformerCache(clientset)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ic.Start(ctx)
	defer ic.Stop()

	ic.mu.RLock()
	podInf := ic.podInf
	esInf := ic.esInf
	ic.mu.RUnlock()
	if podInf == nil || esInf == nil {
		t.Skip("informers not initialized")
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "default", Labels: map[string]string{"app": "x"}},
		Status:     corev1.PodStatus{PodIP: "10.5.5.5"},
	}
	podNoIP := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p2", Namespace: "default"}}
	for _, p := range []*corev1.Pod{pod, podNoIP} {
		if err := podInf.GetIndexer().Add(p); err != nil {
			t.Fatalf("add pod: %v", err)
		}
	}

	if meta := ic.GetPodByIP("10.5.5.5"); meta == nil || meta.Name != "p1" {
		t.Fatalf("expected pod p1 for 10.5.5.5, got %+v", meta)
	}

	port := int32(8080)

	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Name: "svc-abc", Namespace: "default", Labels: map[string]string{serviceNameKey: "svc"}},
		Ports:      []discoveryv1.EndpointPort{{Port: &port}},
		Endpoints:  []discoveryv1.Endpoint{{Addresses: []string{"10.6.6.6"}}},
	}

	esFallback := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Name: "svc2-abc", Namespace: "default", Labels: map[string]string{discoveryv1.LabelServiceName: "svc2"}},
		Ports:      []discoveryv1.EndpointPort{{Port: &port}},
		Endpoints:  []discoveryv1.Endpoint{{Addresses: []string{"", "10.7.7.7"}}},
	}

	esNoPort := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Name: "svc3-abc", Namespace: "default", Labels: map[string]string{serviceNameKey: "svc3"}},
		Endpoints:  []discoveryv1.Endpoint{{Addresses: []string{"10.8.8.8"}}},
	}
	for _, o := range []*discoveryv1.EndpointSlice{es, esFallback, esNoPort} {
		if err := esInf.GetIndexer().Add(o); err != nil {
			t.Fatalf("add endpointslice: %v", err)
		}
	}

	if svc := ic.GetServiceByEndpoint("10.6.6.6", 8080); svc == nil || svc.Name != "svc" {
		t.Errorf("expected svc for 10.6.6.6:8080, got %+v", svc)
	}
	if svc := ic.GetServiceByEndpoint("10.7.7.7", 8080); svc == nil || svc.Name != "svc2" {
		t.Errorf("expected svc2 via LabelServiceName fallback, got %+v", svc)
	}
	if svc := ic.GetServiceByEndpoint("10.8.8.8", 0); svc == nil || svc.Name != "svc3" {
		t.Errorf("expected svc3 via ipOnly index (port=0), got %+v", svc)
	}
}

func TestGetServiceByEndpoint_NoServiceNameLabel(t *testing.T) {
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
	port := int32(7000)
	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Name: "unlabeled", Namespace: "default"},
		Ports:      []discoveryv1.EndpointPort{{Port: &port}},
		Endpoints:  []discoveryv1.Endpoint{{Addresses: []string{"10.4.4.4"}}},
	}
	if err := esInf.GetIndexer().Add(es); err != nil {
		t.Fatalf("add endpointslice: %v", err)
	}
	if svc := ic.GetServiceByEndpoint("10.4.4.4", 7000); svc != nil {
		t.Errorf("expected nil for endpoint slice without a service-name label, got %+v", svc)
	}
}
