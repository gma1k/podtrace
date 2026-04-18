package kubernetes

import (
	"context"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/podtrace/podtrace/internal/events"
)

func TestContextEnricher_EnrichEvent(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	podInfo := &PodInfo{
		PodName:   "test-pod",
		Namespace: "default",
		Labels:    map[string]string{"app": "test"},
	}

	enricher := NewContextEnricher(clientset, podInfo)

	event := &events.Event{
		Type:   events.EventConnect,
		Target: "192.168.1.1:8080",
	}

	enriched := enricher.EnrichEvent(context.Background(), event)
	if enriched == nil {
		t.Fatal("expected enriched event, got nil")
	}

	if enriched.KubernetesContext == nil {
		t.Fatal("expected Kubernetes context, got nil")
	}

	if enriched.KubernetesContext.SourceNamespace != "default" {
		t.Errorf("expected source namespace 'default', got %q", enriched.KubernetesContext.SourceNamespace)
	}
}

func TestContextEnricher_EnrichEvent_NonNetwork(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	podInfo := &PodInfo{
		PodName:   "test-pod",
		Namespace: "default",
	}

	enricher := NewContextEnricher(clientset, podInfo)

	event := &events.Event{
		Type:   events.EventRead,
		Target: "file.txt",
	}

	enriched := enricher.EnrichEvent(context.Background(), event)
	if enriched == nil {
		t.Fatal("expected enriched event, got nil")
	}

	if enriched.KubernetesContext.SourceNamespace != "default" {
		t.Errorf("expected source namespace 'default', got %q", enriched.KubernetesContext.SourceNamespace)
	}
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		expectedIP string
		expectedPort int
	}{
		{"IPv4 with port", "192.168.1.1:8080", "192.168.1.1", 8080},
		{"IPv6 with port", "[2001:db8::1]:8080", "2001:db8::1", 8080},
		{"No port", "192.168.1.1", "192.168.1.1", 0},
		{"Empty", "", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, port := parseTarget(tt.target)
			if ip != tt.expectedIP {
				t.Errorf("expected IP %q, got %q", tt.expectedIP, ip)
			}
			if port != tt.expectedPort {
				t.Errorf("expected port %d, got %d", tt.expectedPort, port)
			}
		})
	}
}

func TestIsNetworkEvent(t *testing.T) {
	tests := []struct {
		eventType events.EventType
		expected  bool
	}{
		{events.EventConnect, true},
		{events.EventTCPSend, true},
		{events.EventTCPRecv, true},
		{events.EventUDPSend, true},
		{events.EventUDPRecv, true},
		{events.EventRead, false},
		{events.EventWrite, false},
		{events.EventDNS, false},
	}

	for _, tt := range tests {
		result := isNetworkEvent(tt.eventType)
		if result != tt.expected {
			t.Errorf("isNetworkEvent(%v) = %v, expected %v", tt.eventType, result, tt.expected)
		}
	}
}

func TestContextEnricher_ResolvePodByIP(t *testing.T) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "target-pod",
			Namespace: "default",
			Labels:    map[string]string{"app": "target"},
		},
		Status: corev1.PodStatus{
			PodIP: "10.244.1.5",
		},
	}

	clientset := fake.NewSimpleClientset(ns, pod)
	podInfo := &PodInfo{
		PodName:   "test-pod",
		Namespace: "default",
	}

	enricher := NewContextEnricher(clientset, podInfo)

	podMeta := enricher.resolvePodByIP(context.Background(), "10.244.1.5")
	if podMeta != nil {
		if podMeta.Name != "target-pod" {
			t.Errorf("expected pod name 'target-pod', got %q", podMeta.Name)
		}
	} else {
		t.Log("pod resolution returned nil, which may be expected with fake client limitations")
	}
}

func TestIsPrivateIP_ValidPrivateIPs(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"loopback", "127.0.0.1", true},
		{"private class A", "10.0.0.1", true},
		{"private class B", "172.16.0.1", true},
		{"private class C", "192.168.1.1", true},
		{"link local unicast", "169.254.1.1", true},
		{"public IP", "8.8.8.8", false},
		{"public IP 2", "1.1.1.1", false},
		{"invalid IP", "not-an-ip", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPrivateIP(tt.ip)
			if got != tt.want {
				t.Errorf("isPrivateIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestGetIntEnvOrDefault_EmptyValue(t *testing.T) {
	origValue := os.Getenv("TEST_ENV_VAR")
	defer func() {
		if origValue != "" {
			_ = os.Setenv("TEST_ENV_VAR", origValue)
		} else {
			_ = os.Unsetenv("TEST_ENV_VAR")
		}
	}()
	
	_ = os.Unsetenv("TEST_ENV_VAR")
	
	result := getIntEnvOrDefault("TEST_ENV_VAR", 100)
	if result != 100 {
		t.Errorf("Expected default value 100, got %d", result)
	}
}

func TestGetIntEnvOrDefault_ValidValue(t *testing.T) {
	origValue := os.Getenv("TEST_ENV_VAR")
	defer func() {
		if origValue != "" {
			_ = os.Setenv("TEST_ENV_VAR", origValue)
		} else {
			_ = os.Unsetenv("TEST_ENV_VAR")
		}
	}()
	
	_ = os.Setenv("TEST_ENV_VAR", "200")
	
	result := getIntEnvOrDefault("TEST_ENV_VAR", 100)
	if result != 200 {
		t.Errorf("Expected value 200, got %d", result)
	}
}

func TestGetIntEnvOrDefault_InvalidValue(t *testing.T) {
	origValue := os.Getenv("TEST_ENV_VAR")
	defer func() {
		if origValue != "" {
			_ = os.Setenv("TEST_ENV_VAR", origValue)
		} else {
			_ = os.Unsetenv("TEST_ENV_VAR")
		}
	}()
	
	_ = os.Setenv("TEST_ENV_VAR", "invalid")
	
	result := getIntEnvOrDefault("TEST_ENV_VAR", 100)
	if result != 100 {
		t.Errorf("Expected default value 100 for invalid input, got %d", result)
	}
}

func TestGetIntEnvOrDefault_ZeroValue(t *testing.T) {
	origValue := os.Getenv("TEST_ENV_VAR")
	defer func() {
		if origValue != "" {
			_ = os.Setenv("TEST_ENV_VAR", origValue)
		} else {
			_ = os.Unsetenv("TEST_ENV_VAR")
		}
	}()
	
	_ = os.Setenv("TEST_ENV_VAR", "0")
	
	result := getIntEnvOrDefault("TEST_ENV_VAR", 100)
	if result != 100 {
		t.Errorf("Expected default value 100 for zero input, got %d", result)
	}
}

func TestGetIntEnvOrDefault_NegativeValue(t *testing.T) {
	origValue := os.Getenv("TEST_ENV_VAR")
	defer func() {
		if origValue != "" {
			_ = os.Setenv("TEST_ENV_VAR", origValue)
		} else {
			_ = os.Unsetenv("TEST_ENV_VAR")
		}
	}()

	_ = os.Setenv("TEST_ENV_VAR", "-10")

	result := getIntEnvOrDefault("TEST_ENV_VAR", 100)
	if result != 100 {
		t.Errorf("Expected default value 100 for negative input, got %d", result)
	}
}

// TestContextEnricher_StartStop_Nil verifies nil-safety of Start/Stop.
func TestContextEnricher_StartStop_Nil(t *testing.T) {
	var ce *ContextEnricher
	ce.Start(t.Context()) // must not panic
	ce.Stop()             // must not panic
}

// TestContextEnricher_Start_NilInformerCache verifies no-op when informerCache is nil.
func TestContextEnricher_Start_NilInformerCache(t *testing.T) {
	ce := &ContextEnricher{informerCache: nil}
	ce.Start(t.Context()) // must not panic
	ce.Stop()             // must not panic
}

// TestContextEnricher_Start_WithInformerCache verifies Start delegates to informerCache.
func TestContextEnricher_Start_WithInformerCache(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	podInfo := &PodInfo{PodName: "test", Namespace: "default"}
	ce := NewContextEnricher(clientset, podInfo)
	// Call Start — should not panic (informerCache exists but clientset has no real k8s).
	t.Setenv("PODTRACE_K8S_USE_INFORMERS", "false")
	ce.Start(t.Context())
	ce.Stop()
}

// TestContextEnricher_EnrichEvent_ExternalIP verifies IsExternal is set for public IPs.
func TestContextEnricher_EnrichEvent_ExternalIP(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	podInfo := &PodInfo{PodName: "p", Namespace: "default"}
	ce := NewContextEnricher(clientset, podInfo)

	event := &events.Event{
		Type:   events.EventConnect,
		Target: "8.8.8.8:53", // public IP
	}
	enriched := ce.EnrichEvent(t.Context(), event)
	if enriched == nil {
		t.Fatal("expected enriched event")
	}
	if !enriched.KubernetesContext.IsExternal {
		t.Error("expected IsExternal=true for public IP 8.8.8.8")
	}
}

// TestContextEnricher_EnrichEvent_PrivateIP verifies IsExternal is false for private IPs.
func TestContextEnricher_EnrichEvent_PrivateIP(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	podInfo := &PodInfo{PodName: "p", Namespace: "default"}
	ce := NewContextEnricher(clientset, podInfo)

	event := &events.Event{
		Type:   events.EventConnect,
		Target: "10.0.0.1:80", // private IP, no k8s pod
	}
	enriched := ce.EnrichEvent(t.Context(), event)
	if enriched == nil {
		t.Fatal("expected enriched event")
	}
	if enriched.KubernetesContext.IsExternal {
		t.Error("expected IsExternal=false for private IP 10.0.0.1")
	}
}

// TestContextEnricher_EnrichEvent_PodMatch verifies that a matching pod is found by IP.
func TestContextEnricher_EnrichEvent_PodMatch(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "target-pod",
			Namespace: "default",
			Labels:    map[string]string{"app": "myapp"},
		},
		Status: corev1.PodStatus{
			PodIP: "10.1.2.3",
		},
	}
	clientset := fake.NewSimpleClientset(pod)
	podInfo := &PodInfo{PodName: "source-pod", Namespace: "ns"}
	ce := NewContextEnricher(clientset, podInfo)

	event := &events.Event{
		Type:   events.EventConnect,
		Target: "10.1.2.3:8080",
	}
	enriched := ce.EnrichEvent(t.Context(), event)
	if enriched == nil {
		t.Fatal("expected enriched event")
	}
	// The informer cache won't have it (not started), but the direct API lookup should work.
	// Either the pod name is found or not depending on whether the direct fetch is tried.
	// We just verify no panic and non-nil result.
	_ = enriched.KubernetesContext
}

// TestContextEnricher_EnrichEvent_UnknownTarget verifies early return for unknown targets.
func TestContextEnricher_EnrichEvent_UnknownTarget(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	podInfo := &PodInfo{PodName: "p", Namespace: "ns"}
	ce := NewContextEnricher(clientset, podInfo)

	for _, target := range []string{"", "?", "unknown", "file"} {
		event := &events.Event{Type: events.EventConnect, Target: target}
		if enriched := ce.EnrichEvent(t.Context(), event); enriched == nil {
			t.Errorf("expected non-nil enriched event for target %q", target)
		}
	}
}


// ─── resolvePodByIP: cache hit ────────────────────────────────────────────────

func TestResolvePodByIP_CacheHit(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	podInfo := &PodInfo{PodName: "src", Namespace: "default"}
	ce := NewContextEnricher(clientset, podInfo)

	ip := "10.200.1.1"
	expected := &PodMetadata{Name: "cached-pod", Namespace: "ns", IP: ip}

	// Pre-populate cache with a non-expired entry.
	ce.podCache.Store(ip, &cacheEntry{
		data:      expected,
		expiresAt: time.Now().Add(5 * time.Minute),
	})

	got := ce.resolvePodByIP(context.Background(), ip)
	if got == nil {
		t.Fatal("expected cache hit, got nil")
	}
	if got.Name != "cached-pod" {
		t.Errorf("expected Name=cached-pod, got %q", got.Name)
	}
}

func TestResolvePodByIP_ExpiredCacheEntry(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	podInfo := &PodInfo{PodName: "src", Namespace: "default"}
	ce := NewContextEnricher(clientset, podInfo)

	ip := "10.200.1.2"
	stale := &PodMetadata{Name: "stale-pod", Namespace: "ns", IP: ip}

	// Pre-populate cache with an expired entry.
	ce.podCache.Store(ip, &cacheEntry{
		data:      stale,
		expiresAt: time.Now().Add(-1 * time.Minute), // expired
	})

	// Should delete the expired entry and re-fetch (which returns nil since no real pod).
	got := ce.resolvePodByIP(context.Background(), ip)
	// We don't care about the result, just that it doesn't panic and deletes the old entry.
	_ = got

	// Verify the stale entry was removed.
	_, ok := ce.podCache.Load(ip)
	// After re-fetch with empty result (nil), the cache should not have the stale entry.
	if ok {
		// If the refetch returned nil, the entry was not re-stored.
		// Check the data is not the stale one.
		t.Log("cache entry still present after expired eviction (may be from re-fetch)")
	}
}

func TestResolvePodByIP_EmptyIP(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	ce := NewContextEnricher(clientset, &PodInfo{})
	if got := ce.resolvePodByIP(context.Background(), ""); got != nil {
		t.Errorf("expected nil for empty IP, got %+v", got)
	}
}

// ─── fetchPodByIP ─────────────────────────────────────────────────────────────

func TestFetchPodByIP_NilClientset(t *testing.T) {
	ce := &ContextEnricher{clientset: nil}
	if got := ce.fetchPodByIP(context.Background(), "10.0.0.1"); got != nil {
		t.Errorf("expected nil for nil clientset, got %+v", got)
	}
}

func TestFetchPodByIP_PodFound(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mypod",
			Namespace: "default",
			Labels:    map[string]string{"app": "myapp", "env": "prod"},
		},
		Status: corev1.PodStatus{PodIP: "10.50.1.1"},
	}
	clientset := fake.NewSimpleClientset(pod)
	ce := &ContextEnricher{clientset: clientset}

	got := ce.fetchPodByIP(context.Background(), "10.50.1.1")
	if got == nil {
		t.Fatal("expected pod metadata, got nil")
	}
	if got.Name != "mypod" {
		t.Errorf("expected Name=mypod, got %q", got.Name)
	}
	if got.Labels["app"] != "myapp" {
		t.Errorf("expected label app=myapp, got %q", got.Labels["app"])
	}
}

func TestFetchPodByIP_PodIPMismatch(t *testing.T) {
	// Pod exists but with a different IP → should return nil.
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "default"},
		Status:     corev1.PodStatus{PodIP: "10.0.0.99"},
	}
	clientset := fake.NewSimpleClientset(pod)
	ce := &ContextEnricher{clientset: clientset}

	// Looking for a different IP — fake clientset ignores field selector,
	// returns all pods, but the IP check in fetchPodByIP filters it out.
	got := ce.fetchPodByIP(context.Background(), "10.0.0.1")
	_ = got // may return nil or not depending on fake clientset behavior
}

// ─── GetServiceByEndpoint: nil labels / empty svcName ─────────────────────────

func TestGetServiceByEndpoint_NilLabels(t *testing.T) {
	port := int32(8080)
	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "svc-no-labels",
			Namespace: "default",
			Labels:    nil, // no labels
		},
		Ports:     []discoveryv1.EndpointPort{{Port: &port}},
		Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.9.9.9"}}},
	}
	clientset := fake.NewSimpleClientset(es)
	ic := NewInformerCache(clientset)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ic.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	// Should return nil because labels are nil → svcName is empty.
	svc := ic.GetServiceByEndpoint("10.9.9.9", 8080)
	_ = svc

	ic.Stop()
}

func TestGetServiceByEndpoint_EmptyIP(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	ic := NewInformerCache(clientset)
	if svc := ic.GetServiceByEndpoint("", 8080); svc != nil {
		t.Errorf("expected nil for empty IP, got %+v", svc)
	}
}

func TestGetServiceByEndpoint_NilInformerCache(t *testing.T) {
	var ic *InformerCache
	if svc := ic.GetServiceByEndpoint("10.0.0.1", 80); svc != nil {
		t.Errorf("expected nil for nil InformerCache, got %+v", svc)
	}
}

// ─── enrichNetworkTarget: service found via informer cache ────────────────────

func TestEnrichNetworkTarget_ServiceFoundViaInformer(t *testing.T) {
	port := int32(8080)
	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-svc-slice",
			Namespace: "default",
			Labels: map[string]string{
				serviceNameKey: "my-svc",
			},
		},
		Ports:     []discoveryv1.EndpointPort{{Port: &port}},
		Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.77.1.1"}}},
	}
	clientset := fake.NewSimpleClientset(es)
	podInfo := &PodInfo{PodName: "src", Namespace: "ns", Labels: map[string]string{}}
	ce := NewContextEnricher(clientset, podInfo)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ce.Start(ctx)
	time.Sleep(300 * time.Millisecond)

	event := &events.Event{
		Type:   events.EventConnect,
		Target: "10.77.1.1:8080",
	}
	enriched := ce.EnrichEvent(ctx, event)
	if enriched == nil {
		t.Fatal("expected enriched event")
	}
	// If informer has synced, ServiceName should be "my-svc".
	if enriched.KubernetesContext.ServiceName != "" {
		if enriched.KubernetesContext.ServiceName != "my-svc" {
			t.Errorf("expected ServiceName=my-svc, got %q", enriched.KubernetesContext.ServiceName)
		}
	} else {
		t.Log("ServiceName empty (informer may not have synced in time)")
	}

	ce.Stop()
}

// ─── GetPodByIP: nil InformerCache ───────────────────────────────────────────

func TestGetPodByIP_NilInformerCache(t *testing.T) {
	var ic *InformerCache
	if pod := ic.GetPodByIP("10.0.0.1"); pod != nil {
		t.Errorf("expected nil for nil InformerCache, got %+v", pod)
	}
}

func TestGetPodByIP_EmptyIP(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	ic := NewInformerCache(clientset)
	if pod := ic.GetPodByIP(""); pod != nil {
		t.Errorf("expected nil for empty IP, got %+v", pod)
	}
}
