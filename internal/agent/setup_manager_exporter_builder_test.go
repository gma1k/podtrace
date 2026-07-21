package agent

import (
	"context"
	"testing"

	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	crconfig "sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/podtrace/podtrace/pkg/exporter/bundle"
)

func TestSetupWithManager_DefaultExporterBuilderInvokable(t *testing.T) {
	scheme, err := newAgentScheme()
	if err != nil {
		t.Fatalf("newAgentScheme: %v", err)
	}
	skipNameValidation := true
	mgr, err := ctrl.NewManager(&rest.Config{Host: "http://127.0.0.1:1"}, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",

		Controller: crconfig.Controller{SkipNameValidation: &skipNameValidation},
	})
	if err != nil {
		t.Skipf("manager construction unavailable in this environment: %v", err)
	}

	r := &AgentReconciler{
		Client:          mgr.GetClient(),
		NodeName:        "node-1",
		SystemNamespace: "podtrace-system",
		Metrics:         NewMetrics(),
	}
	if err := r.SetupWithManager(mgr); err != nil {
		t.Fatalf("SetupWithManager: %v", err)
	}
	if r.ExporterBuilder == nil {
		t.Fatal("ExporterBuilder was not defaulted")
	}

	exp, err := r.ExporterBuilder(&BundlePayload{
		Type:     bundle.TypeOTLP,
		Endpoint: "otel-collector:4318",
		Insecure: true,
	}, CRKey{Namespace: "ns", Name: "cr"})
	if err != nil {
		t.Fatalf("defaulted ExporterBuilder returned error: %v", err)
	}
	if exp == nil {
		t.Fatal("defaulted ExporterBuilder returned a nil exporter")
	}
	_ = exp.Close(context.Background())
}
