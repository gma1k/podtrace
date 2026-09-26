//go:build envtest
// +build envtest

package v1alpha1_test

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func storedTracerConfig(t *testing.T, h *envtestHarness, ctx context.Context, name string, spec map[string]any) *podtracev1alpha1.TracerConfig {
	t.Helper()
	u := &unstructured.Unstructured{}
	u.SetAPIVersion("podtrace.io/v1alpha1")
	u.SetKind("TracerConfig")
	u.SetName(name)
	u.Object["spec"] = spec
	if err := h.client.Create(ctx, u); err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	var got podtracev1alpha1.TracerConfig
	if err := h.client.Get(ctx, types.NamespacedName{Name: name}, &got); err != nil {
		t.Fatalf("get %s: %v", name, err)
	}
	return &got
}

func TestEnvtest_AMinimalTracerConfigIsStoredWithEveryToggleOn(t *testing.T) {
	h := setupEnvtest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	for name, spec := range map[string]map[string]any{
		"no-agent":        {"image": "ghcr.io/gma1k/podtrace:test"},
		"empty-agent":     {"image": "ghcr.io/gma1k/podtrace:test", "agent": map[string]any{}},
		"empty-metrics":   {"image": "ghcr.io/gma1k/podtrace:test", "agent": map[string]any{"metrics": map[string]any{}}},
		"only-exclusions": {"image": "ghcr.io/gma1k/podtrace:test", "agent": map[string]any{"metrics": map[string]any{"excludeNamespaces": []any{"podtrace-system"}}}},
	} {
		t.Run(name, func(t *testing.T) {
			got := storedTracerConfig(t, h, ctx, name, spec)
			a := got.Spec.Agent
			if a.Metrics == nil || a.Metrics.Enabled == nil || a.Metrics.KernelAggregation == nil ||
				a.Metrics.Inspections == nil || a.Metrics.Inspections.Enabled == nil ||
				a.ContinuousProfiling == nil || a.SockOpsRTT == nil {
				t.Fatalf("the API server left a toggle unset: %+v; kubectl get would not show "+
					"what the agent runs", a)
			}
			for _, tg := range toggles() {
				if !tg.read(&got.Spec) {
					t.Errorf("%s is off in the stored object", tg.path)
				}
			}
		})
	}
}

func TestEnvtest_AnExplicitFalseSurvivesTheAPIServer(t *testing.T) {
	h := setupEnvtest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	got := storedTracerConfig(t, h, ctx, "opted-out", map[string]any{
		"image": "ghcr.io/gma1k/podtrace:test",
		"agent": map[string]any{
			"continuousProfiling": false,
			"sockOpsRTT":          false,
			"metrics": map[string]any{
				"enabled":           false,
				"kernelAggregation": false,
				"inspections":       map[string]any{"enabled": false, "alerts": false},
			},
		},
	})
	for _, tg := range toggles() {
		switch tg.path {
		case "agent.continuousProfiling", "agent.sockOpsRTT", "agent.metrics.enabled",
			"agent.metrics.kernelAggregation", "agent.metrics.inspections.enabled",
			"agent.metrics.inspections.alerts":
			if tg.read(&got.Spec) {
				t.Errorf("%s was set to false and came back on", tg.path)
			}
		default:
			if !tg.read(&got.Spec) {
				t.Errorf("%s was left out and came back off", tg.path)
			}
		}
	}
}

func TestEnvtest_AnOptOutWrittenByTheGoClientSurvives(t *testing.T) {
	h := setupEnvtest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tc := &podtracev1alpha1.TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "typed-opt-out"},
		Spec: podtracev1alpha1.TracerConfigSpec{
			Image: "ghcr.io/gma1k/podtrace:test",
			Agent: podtracev1alpha1.AgentSpec{
				Metrics: &podtracev1alpha1.AgentMetricsSpec{Enabled: off()},
			},
		},
	}
	if err := h.client.Create(ctx, tc); err != nil {
		t.Fatalf("create: %v", err)
	}
	var got podtracev1alpha1.TracerConfig
	if err := h.client.Get(ctx, types.NamespacedName{Name: tc.Name}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Spec.Agent.Metrics.MetricsEnabled() {
		t.Error("metrics.enabled=false written through the typed client came back on; a " +
			"plain bool with omitempty would drop it and the schema default would win")
	}
}
