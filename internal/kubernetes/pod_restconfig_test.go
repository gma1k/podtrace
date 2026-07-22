package kubernetes

import (
	"testing"

	"k8s.io/client-go/rest"
)

func TestPodResolver_GetRestConfig(t *testing.T) {
	cfg := &rest.Config{Host: "https://api.example.com"}
	r := &PodResolver{restConfig: cfg}
	if got := r.GetRestConfig(); got != cfg {
		t.Errorf("GetRestConfig returned %p, want the injected config %p", got, cfg)
	}
}

func TestPodResolver_GetRestConfigNil(t *testing.T) {
	r := &PodResolver{}
	if got := r.GetRestConfig(); got != nil {
		t.Errorf("GetRestConfig on a resolver with no config = %+v, want nil", got)
	}
}
