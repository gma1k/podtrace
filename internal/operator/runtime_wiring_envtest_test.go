//go:build envtest
// +build envtest

package operator

import (
	"testing"

	ctrl "sigs.k8s.io/controller-runtime"
	crconfig "sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func connectedManager(t *testing.T) ctrl.Manager {
	t.Helper()
	setupSharedEnvtest(t)
	if testEnv == nil || testEnv.Config == nil {
		t.SkipNow()
	}
	scheme, err := NewScheme()
	if err != nil {
		t.Fatalf("NewScheme: %v", err)
	}
	skipNameValidation := true
	mgr, err := ctrl.NewManager(testEnv.Config, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		// Controller names are validated per binary, not per manager, so
		// wiring a second throwaway manager in the same test run would
		// collide with the names the other envtest cases already claimed.
		Controller: crconfig.Controller{SkipNameValidation: &skipNameValidation},
	})
	if err != nil {
		t.Fatalf("build manager: %v", err)
	}
	return mgr
}

func TestEnvtestRegisterReconcilersWiresEveryController(t *testing.T) {
	if err := registerReconcilers(connectedManager(t), DefaultOptions()); err != nil {
		t.Fatalf("registerReconcilers: %v", err)
	}
}

func TestEnvtestRegisterExporterConfigIndexers(t *testing.T) {
	mgr := connectedManager(t)
	if err := registerExporterConfigIndexers(t.Context(), mgr); err != nil {
		t.Fatalf("registerExporterConfigIndexers: %v", err)
	}
	if err := registerExporterConfigIndexers(t.Context(), mgr); err == nil {
		t.Error("re-registering the same index key must be reported, not silently ignored")
	}
}
