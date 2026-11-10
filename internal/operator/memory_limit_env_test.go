package operator

import (
	"testing"

	corev1 "k8s.io/api/core/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/internal/memlimit"
)

func requireMemoryLimitFromDownwardAPI(t *testing.T, role string, c corev1.Container) {
	t.Helper()
	for _, e := range c.Env {
		if e.Name != memlimit.LimitEnv {
			continue
		}
		if e.ValueFrom == nil || e.ValueFrom.ResourceFieldRef == nil || e.ValueFrom.ResourceFieldRef.Resource != "limits.memory" {
			t.Fatalf("%s %s = %+v, want a resourceFieldRef to limits.memory", role, memlimit.LimitEnv, e)
		}
		if e.ValueFrom.ResourceFieldRef.ContainerName != "" && e.ValueFrom.ResourceFieldRef.ContainerName != c.Name {
			t.Fatalf("%s reads the limit of container %q, not its own", role, e.ValueFrom.ResourceFieldRef.ContainerName)
		}
		return
	}
	t.Fatalf("%s container has no %s: it mounts the host cgroupfs and cannot read its own limit", role, memlimit.LimitEnv)
}

func TestAgentGetsItsMemoryLimitFromTheDownwardAPI(t *testing.T) {
	tc := &podtracev1alpha1.TracerConfig{Spec: podtracev1alpha1.TracerConfigSpec{Image: "ghcr.io/gma1k/podtrace:test"}}
	spec := buildAgentDaemonSetSpec(tc, "podtrace-system")
	requireMemoryLimitFromDownwardAPI(t, "agent", spec.Template.Spec.Containers[0])
}

func TestSessionJobGetsItsMemoryLimitFromTheDownwardAPI(t *testing.T) {
	tc := &podtracev1alpha1.TracerConfig{Spec: podtracev1alpha1.TracerConfigSpec{Image: "ghcr.io/gma1k/podtrace:test"}}
	spec := buildSessionJobSpec(newSession(nil), tc, "node-a", sessionTargets{})
	requireMemoryLimitFromDownwardAPI(t, "session", spec.Template.Spec.Containers[0])
}
