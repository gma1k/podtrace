package chart_test

import (
	"strings"
	"testing"
)

func TestTheAPIServerProxyPolicyIsRenderedOnlyWhenAskedForOnCilium(t *testing.T) {
	cilium := []string{"cilium.io/v2"}
	for name, tt := range map[string]struct {
		apis []string
		set  []string
		want bool
	}{
		"off by default":           {cilium, []string{"networkPolicy.enabled=true"}, false},
		"no Cilium":                {nil, []string{"networkPolicy.enabled=true", "networkPolicy.allowAPIServerProxy=true"}, false},
		"no network policy at all": {cilium, []string{"networkPolicy.allowAPIServerProxy=true"}, false},
		"asked for, on Cilium":     {cilium, []string{"networkPolicy.enabled=true", "networkPolicy.allowAPIServerProxy=true"}, true},
	} {
		t.Run(name, func(t *testing.T) {
			out := string(renderChartWithAPIVersions(t, tt.apis, tt.set...))
			if got := strings.Contains(out, "kind: CiliumNetworkPolicy"); got != tt.want {
				t.Errorf("CiliumNetworkPolicy rendered = %v, want %v", got, tt.want)
			}
			if tt.want {
				for _, needed := range []string{"- kube-apiserver", "- remote-node", `port: "9090"`, "podtrace.io/component: agent"} {
					if !strings.Contains(out, needed) {
						t.Errorf("the policy lacks %q; verified on kind, both entities are needed for "+
							"the API server to reach agents on other nodes", needed)
					}
				}
			}
		})
	}
}
