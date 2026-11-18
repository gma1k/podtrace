//go:build envtest
// +build envtest

package v1alpha1_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func createTracerConfig(ctx context.Context, h *envtestHarness, name string, spec map[string]any) error {
	u := &unstructured.Unstructured{}
	u.SetAPIVersion("podtrace.io/v1alpha1")
	u.SetKind("TracerConfig")
	u.SetName(name)
	u.Object["spec"] = spec
	return h.client.Create(ctx, u)
}

func TestEnvtest_TracerConfigSchemaRules(t *testing.T) {
	h := setupEnvtest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	alerting := func(a map[string]any) map[string]any {
		return map[string]any{"image": "ghcr.io/gma1k/podtrace:test", "agent": map[string]any{"alerting": a}}
	}
	egress := func(e map[string]any) map[string]any {
		return map[string]any{"image": "ghcr.io/gma1k/podtrace:test", "egress": e}
	}
	cases := map[string]struct {
		spec      map[string]any
		wantError string
	}{
		"webhook secret ref": {
			spec: alerting(map[string]any{"enabled": true, "webhookURLSecretRef": map[string]any{"name": "hook", "key": "url"}}),
		},
		"plain webhook url": {
			spec: alerting(map[string]any{"enabled": true, "webhookURL": "https://hooks.example/x"}),
		},
		"both webhook sources": {
			spec: alerting(map[string]any{"enabled": true, "webhookURL": "https://hooks.example/x",
				"webhookURLSecretRef": map[string]any{"name": "hook", "key": "url"}}),
			wantError: "set at most one of webhookURL or webhookURLSecretRef",
		},
		"empty url beside secret ref": {
			spec: alerting(map[string]any{"enabled": true, "webhookURL": "",
				"webhookURLSecretRef": map[string]any{"name": "hook", "key": "url"}}),
		},
		"fleet namespace": {
			spec: map[string]any{"image": "ghcr.io/gma1k/podtrace:test", "systemNamespace": "fleet-b"},
		},
		"namespace that is not a name": {
			spec:      map[string]any{"image": "ghcr.io/gma1k/podtrace:test", "systemNamespace": "Fleet_B"},
			wantError: "spec.systemNamespace",
		},
		"egress proxy": {
			spec: egress(map[string]any{"blockPrivateRanges": true, "proxy": map[string]any{
				"httpProxy": "http://proxy.corp:3128", "httpsProxy": "http://[fd00::1]:3128/", "noProxy": ".svc,10.0.0.0/8"}}),
		},
		"egress block only": {
			spec: egress(map[string]any{"blockPrivateRanges": true}),
		},
		"egress proxy with credentials": {
			spec:      egress(map[string]any{"proxy": map[string]any{"httpsProxy": "http://user:pass@proxy:3128"}}),
			wantError: "spec.egress.proxy.httpsProxy",
		},
		"egress proxy without a host": {
			spec:      egress(map[string]any{"proxy": map[string]any{"httpProxy": "http://:3128"}}),
			wantError: "must be an http or https URL with a host",
		},
		"egress proxy with another scheme": {
			spec:      egress(map[string]any{"proxy": map[string]any{"httpProxy": "socks5://proxy:1080"}}),
			wantError: "spec.egress.proxy.httpProxy",
		},
		"egress no-proxy list alone": {
			spec:      egress(map[string]any{"proxy": map[string]any{"noProxy": ".svc"}}),
			wantError: "set httpProxy, httpsProxy or both",
		},
		"egress no-proxy list with a separator it does not use": {
			spec:      egress(map[string]any{"proxy": map[string]any{"httpProxy": "http://p:1", "noProxy": "a;b"}}),
			wantError: "spec.egress.proxy.noProxy",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := createTracerConfig(ctx, h, "rules-"+strings.ReplaceAll(name, " ", "-"), c.spec)
			if c.wantError == "" {
				if err != nil {
					t.Fatalf("the API server rejected a valid TracerConfig: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantError) {
				t.Fatalf("error = %v, want one containing %q", err, c.wantError)
			}
		})
	}
}
