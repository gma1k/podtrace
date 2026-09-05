package operator

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func operatorClusterRoleGrants(t *testing.T) map[string]map[string]bool {
	t.Helper()
	path := filepath.Join("..", "..", "deploy", "charts", "podtrace", "templates", "operator-rbac.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the operator ClusterRole: %v", err)
	}

	groupRe := regexp.MustCompile(`apiGroups:\s*\[(.*?)\]`)
	resourceRe := regexp.MustCompile(`resources:\s*\[(.*?)\]`)
	verbRe := regexp.MustCompile(`verbs:\s*\[(.*?)\]`)

	unquote := func(list string) []string {
		var out []string
		for _, item := range strings.Split(list, ",") {
			item = strings.TrimSpace(item)
			if len(item) >= 2 && strings.HasPrefix(item, `"`) && strings.HasSuffix(item, `"`) {
				out = append(out, item[1:len(item)-1])
			}
		}
		return out
	}

	held := map[string]map[string]bool{}
	lines := strings.Split(string(raw), "\n")
	var groups, resources []string
	for _, line := range lines {
		if m := groupRe.FindStringSubmatch(line); m != nil {
			groups = unquote(m[1])
			resources = nil
			continue
		}
		if m := resourceRe.FindStringSubmatch(line); m != nil {
			resources = unquote(m[1])
			continue
		}
		if m := verbRe.FindStringSubmatch(line); m != nil {
			for _, g := range groups {
				for _, r := range resources {
					key := g + "/" + r
					if held[key] == nil {
						held[key] = map[string]bool{}
					}
					for _, v := range unquote(m[1]) {
						held[key][v] = true
					}
				}
			}
		}
	}
	return held
}

func TestTheOperatorHoldsEveryPermissionItGrantsTheAgent(t *testing.T) {
	held := operatorClusterRoleGrants(t)
	if len(held) == 0 {
		t.Fatal("parsed no rules from the operator ClusterRole; this guard would pass vacuously")
	}

	for _, rule := range agentClusterRoleRules("podtrace-system") {
		for _, group := range rule.APIGroups {
			for _, resource := range rule.Resources {
				key := group + "/" + resource
				grantedByOperator, present := held[key]
				if !present {
					t.Errorf("the agent is granted %s but the operator does not hold it. "+
						"Kubernetes refuses to let a controller grant a permission it lacks, "+
						"so the agent ClusterRole is rejected, and because the DaemonSet is "+
						"created after the RBAC, the cluster ends up with no agent at all",
						key)
					continue
				}
				for _, verb := range rule.Verbs {
					if !grantedByOperator[verb] && !grantedByOperator["*"] {
						t.Errorf("the agent is granted %s %q but the operator holds only %v",
							key, verb, keysOf(grantedByOperator))
					}
				}
			}
		}
	}
}

func keysOf(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}
