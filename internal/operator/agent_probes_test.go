package operator

import (
	"testing"
	"time"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestTheAgentHasAStartupProbeLongEnoughForASlowLoad(t *testing.T) {
	c := buildAgentDaemonSetSpec(tc(func(*podtracev1alpha1.TracerConfig) {}), "podtrace-system").Template.Spec.Containers[0]

	sp := c.StartupProbe
	if sp == nil || sp.HTTPGet == nil || sp.HTTPGet.Path != "/healthz" {
		t.Fatalf("startup probe = %+v, want an HTTP GET of /healthz; without one the liveness "+
			"probe counts while the eBPF backend is still loading and kills the agent", sp)
	}
	budget := time.Duration(sp.PeriodSeconds*sp.FailureThreshold) * time.Second
	if budget < 3*time.Minute {
		t.Errorf("the startup probe allows %v; attaching hundreds of probes on a busy node takes "+
			"longer than the liveness window alone", budget)
	}
}

func TestLivenessWaitsForStartupAndToleratesASlowReply(t *testing.T) {
	c := buildAgentDaemonSetSpec(tc(func(*podtracev1alpha1.TracerConfig) {}), "podtrace-system").Template.Spec.Containers[0]

	for name, p := range map[string]int32{
		"liveness":  c.LivenessProbe.TimeoutSeconds,
		"readiness": c.ReadinessProbe.TimeoutSeconds,
		"startup":   c.StartupProbe.TimeoutSeconds,
	} {
		if p < 2 {
			t.Errorf("%s probe times out after %ds; the kubelet's one-second default fails a "+
				"healthy agent on a loaded node", name, p)
		}
	}
	if c.LivenessProbe.InitialDelaySeconds != 0 {
		t.Errorf("liveness initialDelaySeconds = %d; the startup probe already holds liveness "+
			"back until the agent is up", c.LivenessProbe.InitialDelaySeconds)
	}
	if c.LivenessProbe.HTTPGet.Path != "/healthz" || c.ReadinessProbe.HTTPGet.Path != "/readyz" {
		t.Error("liveness must probe /healthz and readiness /readyz")
	}
}
