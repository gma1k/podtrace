package operator

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestASessionJobMayUseAsMuchMemoryAsAnAgent(t *testing.T) {
	session := defaultSessionResources().Limits[corev1.ResourceMemory]
	agent := defaultAgentResources().Limits[corev1.ResourceMemory]
	if session.Cmp(agent) < 0 {
		t.Errorf("session memory limit %s is below the agent's %s; a session loads the same eBPF object", session.String(), agent.String())
	}
}
