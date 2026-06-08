package agent

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/podtrace/podtrace/pkg/tracer"
)

// TestAgentSetup_SetupWithManager builds a non-connecting manager (the
// rest.Config points at an unroutable host) and verifies the agent
// reconciler wires its watches without error. Manager construction does
// not dial the apiserver, so this stays a unit test.
func TestAgentSetup_SetupWithManager(t *testing.T) {
	scheme, err := newAgentScheme()
	if err != nil {
		t.Fatalf("newAgentScheme: %v", err)
	}

	cfg := &rest.Config{Host: "http://127.0.0.1:1"}
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
	})
	if err != nil {
		t.Skipf("manager construction unavailable in this environment: %v", err)
	}

	r := &AgentReconciler{
		Client:          mgr.GetClient(),
		NodeName:        "node-1",
		SystemNamespace: "podtrace-system",
	}
	if err := r.SetupWithManager(mgr); err != nil {
		t.Fatalf("SetupWithManager: %v", err)
	}

	if r.ExporterBuilder == nil {
		t.Error("ExporterBuilder not defaulted")
	}
	if r.CgroupResolver == nil {
		t.Error("CgroupResolver not defaulted")
	}
	if r.PodAttributor == nil {
		t.Error("PodAttributor not defaulted")
	}
}

// TestAgentSetup_FallbackLegacyTarget drives the reachable, no-match
// branch: with no pods the loop body never runs, and with a pod whose
// cgroup path cannot be discovered the loop hits its continue arm. On a
// host without a kubepods cgroup root, discoverKubepodsRoot returns ""
// so cgroupPathForPod returns "" deterministically — neither branch
// touches a live cgroup or appends a target.
func TestAgentSetup_FallbackLegacyTarget(t *testing.T) {
	var out tracer.TargetSet
	fallbackLegacyTarget(&out, nil, 12345)
	if len(out) != 0 {
		t.Errorf("fallbackLegacyTarget(no pods) appended %d targets, want 0", len(out))
	}

	pod := &corev1.Pod{}
	pod.Name, pod.Namespace, pod.UID = "p", "ns", "uid-1"
	if discoverKubepodsRoot() != "" {
		t.Skip("host exposes a kubepods cgroup root; skipping no-match branch to avoid live-cgroup dependency")
	}
	fallbackLegacyTarget(&out, []*corev1.Pod{pod}, 12345)
	if len(out) != 0 {
		t.Errorf("fallbackLegacyTarget(unresolvable pod) appended %d targets, want 0", len(out))
	}
}
