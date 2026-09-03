package operator

import (
	"testing"

	corev1 "k8s.io/api/core/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func envMap(env []corev1.EnvVar) map[string]string {
	out := make(map[string]string, len(env))
	for _, e := range env {
		out[e.Name] = e.Value
	}
	return out
}

func TestMetricsEnvEmitsNothingWhenAbsentOrDisabled(t *testing.T) {
	for name, spec := range map[string]*podtracev1alpha1.AgentMetricsSpec{
		"nil":      nil,
		"disabled": {Enabled: false},
		"disabled with other fields set": {
			Enabled:      false,
			SeriesBudget: ptr(int32(999)),
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := metricsEnv(spec); len(got) != 0 {
				t.Errorf("got %v, want no env; a disabled plane must leave the pod "+
					"template byte-identical so it triggers no rollout", envMap(got))
			}
		})
	}
}

func TestMetricsEnvEnabledEmitsOnlyTheFlag(t *testing.T) {
	got := envMap(metricsEnv(&podtracev1alpha1.AgentMetricsSpec{Enabled: true}))

	if got[envMetricsEnabled] != "true" {
		t.Fatalf("%s = %q, want true", envMetricsEnabled, got[envMetricsEnabled])
	}
	if len(got) != 1 {
		t.Errorf("got %v, want only the enable flag when nothing else is set so "+
			"the agent's own defaults apply", got)
	}
}

func TestMetricsEnvRendersEveryField(t *testing.T) {
	got := envMap(metricsEnv(&podtracev1alpha1.AgentMetricsSpec{
		Enabled:           true,
		ExcludeNamespaces: []string{"kube-system", "podtrace-system"},
		SeriesBudget:      ptr(int32(12345)),
		NativeHistograms:  ptr(false),
		Labels:            &podtracev1alpha1.AgentMetricsLabelsSpec{Pod: true, Process: true},
	}))

	for key, want := range map[string]string{
		envMetricsEnabled:           "true",
		envMetricsExcludeNamespaces: "kube-system,podtrace-system",
		envMetricsSeriesBudget:      "12345",
		envMetricsNativeHistograms:  "false",
		envMetricsPodLabel:          "true",
		envMetricsProcessLabel:      "true",
	} {
		if got[key] != want {
			t.Errorf("%s = %q, want %q", key, got[key], want)
		}
	}
}

func TestMetricsEnvOmitsUnsetOptionalsRatherThanGuessing(t *testing.T) {
	got := envMap(metricsEnv(&podtracev1alpha1.AgentMetricsSpec{
		Enabled: true,
		Labels:  &podtracev1alpha1.AgentMetricsLabelsSpec{Pod: false, Process: false},
	}))

	for _, key := range []string{
		envMetricsSeriesBudget,
		envMetricsNativeHistograms,
		envMetricsPodLabel,
		envMetricsProcessLabel,
		envMetricsExcludeNamespaces,
	} {
		if _, present := got[key]; present {
			t.Errorf("%s was emitted despite being unset; the agent's default "+
				"should win rather than the operator restating it", key)
		}
	}
}

func TestExcludedNamespacesCannotSmuggleASeparator(t *testing.T) {
	got := envMap(metricsEnv(&podtracev1alpha1.AgentMetricsSpec{
		Enabled: true,
		ExcludeNamespaces: []string{
			"good",
			"bad,injected",
			"has space",
			"  ",
			"",
			"good",
		},
	}))

	if got[envMetricsExcludeNamespaces] != "good" {
		t.Errorf("%s = %q, want only \"good\"; the list is comma-joined into one "+
			"env var, so a name containing a comma would split into two exclusions",
			envMetricsExcludeNamespaces, got[envMetricsExcludeNamespaces])
	}
}

func TestMetricsEnvIsDeterministic(t *testing.T) {
	spec := &podtracev1alpha1.AgentMetricsSpec{
		Enabled:           true,
		ExcludeNamespaces: []string{"a", "b", "c"},
		SeriesBudget:      ptr(int32(7)),
		NativeHistograms:  ptr(true),
		Labels:            &podtracev1alpha1.AgentMetricsLabelsSpec{Pod: true},
	}

	first := metricsEnv(spec)
	for i := 0; i < 20; i++ {
		next := metricsEnv(spec)
		if len(next) != len(first) {
			t.Fatalf("length varies between calls: %d then %d", len(first), len(next))
		}
		for j := range first {
			if next[j] != first[j] {
				t.Fatalf("env order varies at index %d: %v then %v; a non-deterministic "+
					"pod template would roll the DaemonSet on every reconcile",
					j, first[j], next[j])
			}
		}
	}
}

func ptr[T any](v T) *T { return &v }
