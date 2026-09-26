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

func TestMetricsEnvSaysOffExplicitlyWhenDisabled(t *testing.T) {
	for name, spec := range map[string]*podtracev1alpha1.AgentMetricsSpec{
		"disabled": {Enabled: ptr(false)},
		"disabled with other fields set": {
			Enabled:      ptr(false),
			SeriesBudget: ptr(int32(999)),
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := envMap(metricsEnv(spec))
			if len(got) != 1 || got[envMetricsEnabled] != "false" {
				t.Errorf("got %v, want only %s=false; the agent must be told the plane is off "+
					"rather than left to its own default", got, envMetricsEnabled)
			}
		})
	}
}

func TestMetricsEnvTreatsAMissingSpecAsEveryDefault(t *testing.T) {
	for name, spec := range map[string]*podtracev1alpha1.AgentMetricsSpec{
		"nil":   nil,
		"empty": {},
	} {
		t.Run(name, func(t *testing.T) {
			got := envMap(metricsEnv(spec))
			for key, want := range map[string]string{
				envMetricsEnabled:           "true",
				envMetricsNativeHistograms:  "true",
				envMetricsKernelAggregation: "true",
				envInspectionsEnabled:       "true",
				envInspectionsAlerts:        "true",
			} {
				if got[key] != want {
					t.Errorf("%s = %q, want %q; a TracerConfig written without the chart "+
						"would run with the plane off", key, got[key], want)
				}
			}
		})
	}
}

func TestMetricsEnvWritesEveryToggleOut(t *testing.T) {
	got := envMap(metricsEnv(&podtracev1alpha1.AgentMetricsSpec{Enabled: ptr(true)}))

	for _, key := range []string{
		envMetricsEnabled,
		envMetricsNativeHistograms,
		envMetricsKernelAggregation,
		envInspectionsEnabled,
		envInspectionsAlerts,
	} {
		if _, present := got[key]; !present {
			t.Errorf("%s was left out, so the agent's built-in default would decide it and "+
				"changing that default would change every cluster silently", key)
		}
	}
}

func TestMetricsEnvRendersEveryField(t *testing.T) {
	got := envMap(metricsEnv(&podtracev1alpha1.AgentMetricsSpec{
		Enabled:           ptr(true),
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
		Enabled: ptr(true),
		Labels:  &podtracev1alpha1.AgentMetricsLabelsSpec{Pod: false, Process: false},
	}))

	for _, key := range []string{
		envMetricsSeriesBudget,
		envMetricsPodLabel,
		envMetricsProcessLabel,
		envMetricsExcludeNamespaces,
	} {
		if _, present := got[key]; present {
			t.Errorf("%s was emitted despite being unset; a tuning value the user did not "+
				"give should stay the agent's", key)
		}
	}
}

func TestExcludedNamespacesCannotSmuggleASeparator(t *testing.T) {
	got := envMap(metricsEnv(&podtracev1alpha1.AgentMetricsSpec{
		Enabled: ptr(true),
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
		Enabled:           ptr(true),
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

func TestMetricsEnvRendersSemanticConventions(t *testing.T) {
	got := envMap(metricsEnv(&podtracev1alpha1.AgentMetricsSpec{
		Enabled:              ptr(true),
		SemanticConventions:  true,
		AttributeCardinality: ptr(int32(25)),
	}))

	if got[envMetricsSemanticConv] != "true" {
		t.Errorf("%s = %q, want true", envMetricsSemanticConv, got[envMetricsSemanticConv])
	}
	if got[envMetricsAttributeLimit] != "25" {
		t.Errorf("%s = %q, want 25", envMetricsAttributeLimit, got[envMetricsAttributeLimit])
	}
}

func TestSemanticConventionsAbsentWhenNotRequested(t *testing.T) {
	got := envMap(metricsEnv(&podtracev1alpha1.AgentMetricsSpec{Enabled: ptr(true)}))

	for _, key := range []string{envMetricsSemanticConv, envMetricsAttributeLimit} {
		if _, present := got[key]; present {
			t.Errorf("%s rendered without being requested; dual emission doubles the "+
				"L7 series and must stay opt-in", key)
		}
	}
}

func TestMetricsEnvRendersKernelAggregation(t *testing.T) {
	env := metricsEnv(&podtracev1alpha1.AgentMetricsSpec{
		Enabled:           ptr(true),
		KernelAggregation: ptr(true),
	})

	var found bool
	for _, e := range env {
		if e.Name == envMetricsKernelAggregation {
			found = true
			if e.Value != "true" {
				t.Errorf("%s = %q, want true", e.Name, e.Value)
			}
		}
	}
	if !found {
		t.Errorf("%s absent; the CRD field would be accepted and silently ignored, leaving the "+
			"agent on the event path while the spec says otherwise", envMetricsKernelAggregation)
	}
}

func TestMetricsEnvTurnsKernelAggregationOffWhenAsked(t *testing.T) {
	got := envMap(metricsEnv(&podtracev1alpha1.AgentMetricsSpec{
		Enabled:           ptr(true),
		KernelAggregation: ptr(false),
	}))
	if got[envMetricsKernelAggregation] != "false" {
		t.Errorf("%s = %q, want false; an explicit opt-out must reach the agent",
			envMetricsKernelAggregation, got[envMetricsKernelAggregation])
	}
}
