package operator

import (
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"sigs.k8s.io/yaml"
)

type chartValues struct {
	Agent struct {
		Resources corev1.ResourceRequirements `json:"resources"`
	} `json:"agent"`
	Session struct {
		Resources corev1.ResourceRequirements `json:"resources"`
	} `json:"session"`
}

func loadChartValues(t *testing.T) chartValues {
	t.Helper()
	path := filepath.Join("..", "..", "deploy", "charts", "podtrace", "values.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var values chartValues
	if err := yaml.Unmarshal(raw, &values); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return values
}

func assertQuantitiesEqual(t *testing.T, field string, got, want resource.Quantity) {
	t.Helper()
	if got.Cmp(want) != 0 {
		t.Errorf("%s = %s, chart values.yaml says %s; the bootstrap defaults apply on OLM and raw-kubectl installs, where nothing else fills them in, and an under-sized memory limit OOMKills the agent while it loads its BPF objects",
			field, got.String(), want.String())
	}
}

func assertResourcesMatchChart(t *testing.T, kind string, got, want corev1.ResourceRequirements) {
	t.Helper()
	for _, tt := range []struct {
		field string
		got   resource.Quantity
		want  resource.Quantity
	}{
		{kind + " requests.cpu", got.Requests[corev1.ResourceCPU], want.Requests[corev1.ResourceCPU]},
		{kind + " requests.memory", got.Requests[corev1.ResourceMemory], want.Requests[corev1.ResourceMemory]},
		{kind + " limits.cpu", got.Limits[corev1.ResourceCPU], want.Limits[corev1.ResourceCPU]},
		{kind + " limits.memory", got.Limits[corev1.ResourceMemory], want.Limits[corev1.ResourceMemory]},
	} {
		assertQuantitiesEqual(t, tt.field, tt.got, tt.want)
	}
}

func TestBootstrapAgentResourcesMatchChartDefaults(t *testing.T) {
	assertResourcesMatchChart(t, "agent", defaultAgentResources(), loadChartValues(t).Agent.Resources)
}

func TestBootstrapSessionResourcesMatchChartDefaults(t *testing.T) {
	assertResourcesMatchChart(t, "session", defaultSessionResources(), loadChartValues(t).Session.Resources)
}
