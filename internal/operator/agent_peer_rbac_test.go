package operator

import "testing"

func TestAgentMayReadEndpointSlicesForTheServiceMap(t *testing.T) {
	var verbs []string
	for _, rule := range agentClusterRoleRules("podtrace-system") {
		for _, resource := range rule.Resources {
			if resource != "endpointslices" {
				continue
			}
			for _, group := range rule.APIGroups {
				if group != "discovery.k8s.io" {
					t.Errorf("endpointslices granted under API group %q, want discovery.k8s.io",
						group)
				}
			}
			verbs = append(verbs, rule.Verbs...)
		}
	}

	if len(verbs) == 0 {
		t.Fatal("the agent has no grant on endpointslices. The service map resolves a peer " +
			"address to the Service that owns it, so without this every edge silently " +
			"collapses to unresolved rather than failing visibly")
	}

	granted := map[string]bool{}
	for _, verb := range verbs {
		granted[verb] = true
	}
	for _, required := range []string{"get", "list", "watch"} {
		if !granted[required] {
			t.Errorf("endpointslices grant is missing %q; the resolver reads through a watched "+
				"cache", required)
		}
	}
	for _, forbidden := range []string{"create", "update", "patch", "delete", "*"} {
		if granted[forbidden] {
			t.Errorf("endpointslices grant includes %q. This is a cluster-wide grant on every "+
				"namespace's service endpoints, and the agent only ever reads them", forbidden)
		}
	}
}
