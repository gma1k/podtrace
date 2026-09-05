package operator

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func agentDaemonSetSpecForLabels(t *testing.T) (map[string]string, map[string]string) {
	t.Helper()
	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       podtracev1alpha1.TracerConfigSpec{Image: "ghcr.io/gma1k/podtrace:test"},
	}
	spec := buildAgentDaemonSetSpec(tc, "podtrace-system")
	return spec.Selector.MatchLabels, spec.Template.Labels
}

func TestAgentPodsCarryTheStandardLabelConvention(t *testing.T) {
	_, pod := agentDaemonSetSpecForLabels(t)

	want := map[string]string{
		"app.kubernetes.io/name":       "podtrace",
		"app.kubernetes.io/component":  ComponentAgent,
		"app.kubernetes.io/part-of":    "podtrace",
		"app.kubernetes.io/managed-by": ManagedByValue,
	}
	for k, v := range want {
		if pod[k] != v {
			t.Errorf("pod label %s = %q, want %q. The operator's own pods use this convention, "+
				"so an agent without it is invisible to any selector, NetworkPolicy or "+
				"ServiceMonitor written the usual way", k, pod[k], v)
		}
	}
}

func TestAgentPodsKeepTheirPodtraceLabels(t *testing.T) {
	selector, pod := agentDaemonSetSpecForLabels(t)

	for k, v := range selector {
		if pod[k] != v {
			t.Errorf("pod label %s = %q, want %q; the pod must still satisfy its own selector",
				k, pod[k], v)
		}
	}
}

func TestTheDaemonSetSelectorGainsNoNewLabels(t *testing.T) {
	selector, _ := agentDaemonSetSpecForLabels(t)

	if len(selector) != 3 {
		t.Fatalf("selector = %v, want exactly 3 labels. spec.selector is immutable, so a label "+
			"added here can only be applied by deleting and recreating the DaemonSet, "+
			"restarting a privileged pod on every node", selector)
	}
	for k := range selector {
		if len(k) > 18 && k[:18] == "app.kubernetes.io/" {
			t.Errorf("selector gained %q; the convention labels belong on the pod template only", k)
		}
	}
}

func TestPodTemplateLabelsAreACopy(t *testing.T) {
	selector := map[string]string{"a": "1"}
	pod := agentPodTemplateLabels(selector)
	pod["b"] = "2"

	if _, leaked := selector["b"]; leaked {
		t.Error("writing to the pod labels mutated the selector; they share a map, and the " +
			"selector is immutable once the DaemonSet exists")
	}
}
