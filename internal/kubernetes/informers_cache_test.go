package kubernetes

import (
	"testing"
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
