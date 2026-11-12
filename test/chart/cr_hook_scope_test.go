package chart_test

import (
	"slices"
	"strings"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

func TestCRBootstrapCanOnlyChangeTheObjectsItApplies(t *testing.T) {
	cases := []struct {
		name  string
		flags []string
		want  map[string][]string
	}{
		{
			name:  "defaults",
			flags: nil,
			want:  map[string][]string{"tracerconfigs": {"default"}},
		},
		{
			name:  "empty tracerConfig name",
			flags: []string{"tracerConfig.name="},
			want:  map[string][]string{"tracerconfigs": {"default"}},
		},
		{
			name: "named fleet with the example ExporterConfig",
			flags: []string{
				"tracerConfig.name=fleet",
				"examples.exporterconfig.enabled=true",
				"examples.exporterconfig.name=demo",
			},
			want: map[string][]string{"tracerconfigs": {"fleet"}, "exporterconfigs": {"demo"}},
		},
		{
			name:  "example ExporterConfig only",
			flags: []string{"tracerConfig.create=false", "examples.exporterconfig.enabled=true"},
			want:  map[string][]string{"exporterconfigs": {"starter-otlp"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var role rbacv1.ClusterRole
			mustFindObject(t, renderChart(t, tc.flags...), "ClusterRole", "podtrace-cr-bootstrap").decode(t, &role)

			got := map[string][]string{}
			for _, rule := range role.Rules {
				if len(rule.ResourceNames) == 0 {
					if !slices.Equal(rule.Verbs, []string{"create"}) {
						t.Errorf("unnamed rule grants %v on %v; only create may be unscoped, or the hook "+
							"can rewrite any TracerConfig and so the agent image", rule.Verbs, rule.Resources)
					}
					continue
				}
				if slices.Contains(rule.Verbs, "create") || slices.Contains(rule.Verbs, "list") {
					t.Errorf("named rule grants %v; create and list cannot be narrowed by name", rule.Verbs)
				}
				for _, resource := range rule.Resources {
					got[resource] = append(got[resource], rule.ResourceNames...)
				}
			}
			for resource, names := range tc.want {
				if !slices.Equal(got[resource], names) {
					t.Errorf("%s names %v, want %v", resource, got[resource], names)
				}
			}
			for resource := range got {
				if _, ok := tc.want[resource]; !ok {
					t.Errorf("unexpected named rule on %s: %v", resource, got[resource])
				}
			}
		})
	}
}

func TestCRTeardownDeletesOnlyTheBootstrappedTracerConfig(t *testing.T) {
	for flag, want := range map[string]string{
		"tracerConfig.name=":      "default",
		"tracerConfig.name=fleet": "fleet",
	} {
		t.Run(flag, func(t *testing.T) {
			out := renderChart(t, flag)

			var role rbacv1.ClusterRole
			mustFindObject(t, out, "ClusterRole", "podtrace-cr-teardown").decode(t, &role)
			for _, rule := range role.Rules {
				if !slices.Equal(rule.ResourceNames, []string{want}) {
					t.Errorf("rule %v names %v, want only %q", rule.Verbs, rule.ResourceNames, want)
				}
			}

			var job batchv1.Job
			mustFindObject(t, out, "Job", "podtrace-cr-teardown").decode(t, &job)
			command := job.Spec.Template.Spec.Containers[0].Command
			script := command[len(command)-1]
			if !strings.Contains(script, `kubectl delete tracerconfig "`+want+`"`) {
				t.Errorf("teardown does not delete TracerConfig %q:\n%s", want, script)
			}
		})
	}
}
