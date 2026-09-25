package operator

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestContinuousProfilingReachesTheAgentEnvironment(t *testing.T) {
	on := true
	spec := buildAgentDaemonSetSpec(tc(func(x *podtracev1alpha1.TracerConfig) {
		x.Spec.Agent.ContinuousProfiling = &on
	}), "podtrace-system")

	if v, ok := envValue(spec.Template.Spec.Containers[0].Env,
		"PODTRACE_CONTINUOUS_PROFILING_ENABLED"); !ok || v != "true" {
		t.Errorf("PODTRACE_CONTINUOUS_PROFILING_ENABLED=%q ok=%v want true.\n\n"+
			"The operator owns the agent DaemonSet and reverts hand-edited env, so a "+
			"feature with no path from the CRD to here cannot be turned on at all.", v, ok)
	}
}

func TestSockOpsRTTReachesTheAgentEnvironment(t *testing.T) {
	on := true
	spec := buildAgentDaemonSetSpec(tc(func(x *podtracev1alpha1.TracerConfig) {
		x.Spec.Agent.SockOpsRTT = &on
	}), "podtrace-system")

	if v, ok := envValue(spec.Template.Spec.Containers[0].Env,
		"PODTRACE_SOCKOPS_RTT_ENABLED"); !ok || v != "true" {
		t.Errorf("PODTRACE_SOCKOPS_RTT_ENABLED=%q ok=%v want true", v, ok)
	}
}

func TestNeitherProfilingNorSockOpsIsOnByDefault(t *testing.T) {
	spec := buildAgentDaemonSetSpec(tc(func(x *podtracev1alpha1.TracerConfig) {}), "podtrace-system")

	for _, name := range []string{
		"PODTRACE_CONTINUOUS_PROFILING_ENABLED",
		"PODTRACE_SOCKOPS_RTT_ENABLED",
	} {
		if v, ok := envValue(spec.Template.Spec.Containers[0].Env, name); ok {
			t.Errorf("%s=%q was set without being asked for; both cost per-event work "+
				"and must stay opt-in", name, v)
		}
	}
}

func TestExplicitlyDisablingThemSetsNothing(t *testing.T) {
	off := false
	spec := buildAgentDaemonSetSpec(tc(func(x *podtracev1alpha1.TracerConfig) {
		x.Spec.Agent.ContinuousProfiling = &off
		x.Spec.Agent.SockOpsRTT = &off
	}), "podtrace-system")

	for _, name := range []string{
		"PODTRACE_CONTINUOUS_PROFILING_ENABLED",
		"PODTRACE_SOCKOPS_RTT_ENABLED",
	} {
		if _, ok := envValue(spec.Template.Spec.Containers[0].Env, name); ok {
			t.Errorf("%s was set while the field said false", name)
		}
	}
}

func TestTheNewInspectionThresholdsReachTheAgentEnvironment(t *testing.T) {
	pct := int32(70)
	env := metricsEnv(&podtracev1alpha1.AgentMetricsSpec{
		Enabled: true,
		Inspections: &podtracev1alpha1.AgentInspectionsSpec{
			Enabled: true,
			Thresholds: &podtracev1alpha1.AgentInspectionThresholdsSpec{
				CPUBlockedMean:         &metav1.Duration{Duration: 250 * time.Millisecond},
				PoolUtilizationPercent: &pct,
			},
		},
	})

	if v, ok := envValue(env, "PODTRACE_INSPECTIONS_CPU_BLOCKED_MEAN"); !ok || v != "250ms" {
		t.Errorf("PODTRACE_INSPECTIONS_CPU_BLOCKED_MEAN=%q ok=%v want 250ms", v, ok)
	}
	if v, ok := envValue(env, "PODTRACE_INSPECTIONS_POOL_UTILIZATION_PCT"); !ok || v != "70" {
		t.Errorf("PODTRACE_INSPECTIONS_POOL_UTILIZATION_PCT=%q ok=%v want 70", v, ok)
	}
}

func TestUnsetInspectionThresholdsLeaveTheAgentOnItsDefaults(t *testing.T) {
	env := metricsEnv(&podtracev1alpha1.AgentMetricsSpec{
		Enabled:     true,
		Inspections: &podtracev1alpha1.AgentInspectionsSpec{Enabled: true},
	})

	for _, name := range []string{
		"PODTRACE_INSPECTIONS_CPU_BLOCKED_MEAN",
		"PODTRACE_INSPECTIONS_POOL_UTILIZATION_PCT",
	} {
		if v, ok := envValue(env, name); ok {
			t.Errorf("%s=%q was set from an unset field, pinning the agent to a value "+
				"nobody chose", name, v)
		}
	}
}
