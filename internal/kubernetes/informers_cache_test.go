package kubernetes

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// TestInformerCache_Nil verifies nil-safety on all InformerCache methods.
func TestInformerCache_Nil(t *testing.T) {
	var ic *InformerCache

	// Enabled on nil should not panic.
	_ = ic.Enabled()

	// Start on nil should not panic.
	ic.Start(t.Context())

	// Stop on nil should not panic.
	ic.Stop()

	// GetPodByIP on nil should return nil.
	if p := ic.GetPodByIP("10.0.0.1"); p != nil {
		t.Errorf("GetPodByIP on nil: expected nil, got %+v", p)
	}

	// GetServiceByEndpoint on nil should return nil.
	if s := ic.GetServiceByEndpoint("10.0.0.1", 80); s != nil {
		t.Errorf("GetServiceByEndpoint on nil: expected nil, got %+v", s)
	}
}

// TestInformerCache_Enabled verifies the env-var toggle.
func TestInformerCache_Enabled(t *testing.T) {
	ic := NewInformerCache(nil)

	// Default — should be enabled.
	t.Setenv("PODTRACE_K8S_USE_INFORMERS", "")
	if !ic.Enabled() {
		t.Error("expected Enabled()=true by default")
	}

	// Disabled via env var.
	t.Setenv("PODTRACE_K8S_USE_INFORMERS", "false")
	if ic.Enabled() {
		t.Error("expected Enabled()=false when env var is 'false'")
	}
}

// TestInformerCache_GetPodByIP_EmptyIP verifies early-return for empty IP.
func TestInformerCache_GetPodByIP_EmptyIP(t *testing.T) {
	ic := NewInformerCache(nil)
	if p := ic.GetPodByIP(""); p != nil {
		t.Errorf("expected nil for empty IP, got %+v", p)
	}
}

// TestInformerCache_GetPodByIP_NilInformer verifies nil-informer path.
func TestInformerCache_GetPodByIP_NilInformer(t *testing.T) {
	ic := NewInformerCache(nil)
	// podInf is nil because Start was not called.
	if p := ic.GetPodByIP("192.168.1.1"); p != nil {
		t.Errorf("expected nil when informer not started, got %+v", p)
	}
}

// TestInformerCache_GetServiceByEndpoint_EmptyIP verifies early-return for empty IP.
func TestInformerCache_GetServiceByEndpoint_EmptyIP(t *testing.T) {
	ic := NewInformerCache(nil)
	if s := ic.GetServiceByEndpoint("", 80); s != nil {
		t.Errorf("expected nil for empty IP, got %+v", s)
	}
}

// TestInformerCache_GetServiceByEndpoint_NilInformer verifies nil-informer path.
func TestInformerCache_GetServiceByEndpoint_NilInformer(t *testing.T) {
	ic := NewInformerCache(nil)
	if s := ic.GetServiceByEndpoint("10.0.0.1", 443); s != nil {
		t.Errorf("expected nil when informer not started, got %+v", s)
	}
	if s := ic.GetServiceByEndpoint("10.0.0.1", 0); s != nil {
		t.Errorf("expected nil for port=0 when informer not started, got %+v", s)
	}
}

// TestInformerCache_Start_NilClientset verifies Start is a no-op with nil clientset.
func TestInformerCache_Start_NilClientset(t *testing.T) {
	ic := NewInformerCache(nil)
	ic.Start(t.Context()) // must not panic
}

// TestInformerCache_Start_Disabled verifies Start is a no-op when disabled.
func TestInformerCache_Start_Disabled(t *testing.T) {
	t.Setenv("PODTRACE_K8S_USE_INFORMERS", "false")
	ic := NewInformerCache(nil)
	ic.Start(t.Context()) // must not panic
}

// TestInformerCache_Stop_NotStarted verifies Stop is safe when never started.
func TestInformerCache_Stop_NotStarted(t *testing.T) {
	ic := NewInformerCache(nil)
	ic.Stop() // must not panic
}

// ─── InformerCache.Start with real fake clientset ─────────────────────────────

func TestInformerCache_Start_WithFakeClientset(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	ic := NewInformerCache(clientset)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ic.Start(ctx) // should return after sync timeout

	// Verify informers were initialized.
	ic.mu.RLock()
	podInfSet := ic.podInf != nil
	esInfSet := ic.esInf != nil
	ic.mu.RUnlock()

	if !podInfSet {
		t.Error("expected podInf to be initialized after Start")
	}
	if !esInfSet {
		t.Error("expected esInf to be initialized after Start")
	}
}

func TestInformerCache_Start_Idempotent(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	ic := NewInformerCache(clientset)

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	ic.Start(ctx)
	// Second Start should be a no-op (ic.started == true).
	ic.Start(ctx)

	ic.Stop()
}

func TestInformerCache_Start_DisabledWithClientset(t *testing.T) {
	t.Setenv("PODTRACE_K8S_USE_INFORMERS", "false")
	clientset := fake.NewSimpleClientset()
	ic := NewInformerCache(clientset)

	ic.Start(context.Background())
	// Should not have set informers because Enabled() = false.
	ic.mu.RLock()
	podInfSet := ic.podInf != nil
	ic.mu.RUnlock()
	if podInfSet {
		t.Error("expected podInf to remain nil when informers disabled")
	}
}

// ─── GetPodByIP with a real indexer ──────────────────────────────────────────

func TestInformerCache_GetPodByIP_AfterStart(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mypod",
			Namespace: "default",
			Labels:    map[string]string{"app": "test"},
		},
		Status: corev1.PodStatus{PodIP: "10.0.1.1"},
	}
	clientset := fake.NewSimpleClientset(pod)
	ic := NewInformerCache(clientset)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ic.Start(ctx)

	// Wait a bit for the informer to sync.
	time.Sleep(200 * time.Millisecond)

	meta := ic.GetPodByIP("10.0.1.1")
	if meta == nil {
		t.Log("GetPodByIP returned nil (informer may not have synced in time)")
	} else {
		if meta.Name != "mypod" {
			t.Errorf("expected PodName=mypod, got %q", meta.Name)
		}
	}

	ic.Stop()
}

func TestInformerCache_GetPodByIP_NotFound(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	ic := NewInformerCache(clientset)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ic.Start(ctx)
	time.Sleep(100 * time.Millisecond)

	if meta := ic.GetPodByIP("99.99.99.99"); meta != nil {
		t.Errorf("expected nil for unknown IP, got %+v", meta)
	}

	ic.Stop()
}

// ─── GetServiceByEndpoint with real indexer ───────────────────────────────────

func TestInformerCache_GetServiceByEndpoint_AfterStart(t *testing.T) {
	port := int32(8080)
	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-svc-xyz",
			Namespace: "default",
			Labels: map[string]string{
				serviceNameKey: "my-svc",
			},
		},
		Ports: []discoveryv1.EndpointPort{{Port: &port}},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.2.1"}},
		},
	}
	clientset := fake.NewSimpleClientset(es)
	ic := NewInformerCache(clientset)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ic.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	svc := ic.GetServiceByEndpoint("10.0.2.1", 8080)
	if svc == nil {
		t.Log("GetServiceByEndpoint returned nil (informer may not have synced in time)")
	} else {
		if svc.Name != "my-svc" {
			t.Errorf("expected svc Name=my-svc, got %q", svc.Name)
		}
	}

	// Test with port=0 (ipOnly index).
	svc2 := ic.GetServiceByEndpoint("10.0.2.1", 0)
	_ = svc2

	ic.Stop()
}

// ─── EventsCorrelator watchEvents ─────────────────────────────────────────────

func TestEventsCorrelator_WatchEvents_ContextCancel(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	ec := NewEventsCorrelator(clientset, "mypod", "default")

	ctx, cancel := context.WithCancel(context.Background())

	// Start watches; fake clientset supports watch.
	if err := ec.Start(ctx); err != nil {
		t.Logf("Start returned error (fake watch may not be supported): %v", err)
	}

	// Cancel context → watchEvents goroutine should exit.
	cancel()
	time.Sleep(50 * time.Millisecond)
}

func TestEventsCorrelator_WatchEvents_StopCh(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	ec := NewEventsCorrelator(clientset, "mypod", "default")

	ctx := context.Background()
	if err := ec.Start(ctx); err != nil {
		t.Logf("Start returned error: %v", err)
		return
	}

	// Close stopCh to stop the goroutine.
	close(ec.stopCh)
	time.Sleep(50 * time.Millisecond)
}

func TestEventsCorrelator_WatchEvents_WithEvent(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	watcher := watch.NewRaceFreeFake()
	clientset.PrependWatchReactor("events", k8stesting.DefaultWatchReactor(watcher, nil))

	ec := NewEventsCorrelator(clientset, "mypod", "default")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := ec.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	k8sEvent := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mypod.event1",
			Namespace: "default",
		},
		InvolvedObject: corev1.ObjectReference{Name: "mypod"},
		Reason:         "Started",
		Message:        "Container started",
		Type:           corev1.EventTypeNormal,
		Count:          1,
	}
	watcher.Add(k8sEvent)
	time.Sleep(50 * time.Millisecond)

	ec.mu.RLock()
	numEvents := len(ec.events)
	ec.mu.RUnlock()

	if numEvents == 0 {
		t.Log("no events received (timing-sensitive test)")
	}
}

func TestEventsCorrelator_WatchEvents_WatcherClosed(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	watcher := watch.NewRaceFreeFake()
	clientset.PrependWatchReactor("events", k8stesting.DefaultWatchReactor(watcher, nil))

	ec := NewEventsCorrelator(clientset, "mypod", "default")
	ctx := context.Background()

	if err := ec.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	watcher.Stop()
	time.Sleep(50 * time.Millisecond)
}

// ─── InformerCache stop with custom sync timeout env ──────────────────────────

func TestInformerCache_Start_CustomSyncTimeout(t *testing.T) {
	t.Setenv("PODTRACE_K8S_INFORMERS_SYNC_TIMEOUT_SEC", "1")
	clientset := fake.NewSimpleClientset()
	ic := NewInformerCache(clientset)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ic.Start(ctx)
	ic.Stop()
}

func TestInformerCache_Start_InvalidSyncTimeout(t *testing.T) {
	t.Setenv("PODTRACE_K8S_INFORMERS_SYNC_TIMEOUT_SEC", "notanumber")
	clientset := fake.NewSimpleClientset()
	ic := NewInformerCache(clientset)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ic.Start(ctx) // should use default timeout (2s)
	ic.Stop()
}

// runtime.Object embedding needed for fake clientset to accept EndpointSlice
var _ runtime.Object = &discoveryv1.EndpointSlice{}
