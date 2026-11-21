package operator

import (
	"testing"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestMetricsEnvRendersTheContainerRowBudget(t *testing.T) {
	for name, tc := range map[string]struct {
		budget int32
		want   string
	}{
		"set":      {budget: 512, want: "512"},
		"disabled": {budget: 0, want: "0"},
	} {
		t.Run(name, func(t *testing.T) {
			got := envMap(metricsEnv(&podtracev1alpha1.AgentMetricsSpec{
				Enabled:            ptr(true),
				ContainerRowBudget: ptr(tc.budget),
			}))
			if got[envMetricsContainerRows] != tc.want {
				t.Errorf("%s = %q, want %q", envMetricsContainerRows, got[envMetricsContainerRows], tc.want)
			}
		})
	}
}

func TestMetricsEnvLeavesTheContainerRowBudgetToTheAgentWhenUnset(t *testing.T) {
	got := envMap(metricsEnv(&podtracev1alpha1.AgentMetricsSpec{Enabled: ptr(true)}))
	if value, present := got[envMetricsContainerRows]; present {
		t.Errorf("%s = %q rendered without being set", envMetricsContainerRows, value)
	}
}

func TestMetricsEnvDropsTheContainerRowBudgetWhenThePlaneIsOff(t *testing.T) {
	got := envMap(metricsEnv(&podtracev1alpha1.AgentMetricsSpec{
		Enabled:            ptr(false),
		ContainerRowBudget: ptr(int32(512)),
	}))
	if _, present := got[envMetricsContainerRows]; present {
		t.Errorf("%s rendered while the plane is off", envMetricsContainerRows)
	}
}
