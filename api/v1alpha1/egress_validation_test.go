package v1alpha1

import (
	"strings"
	"testing"
)

func TestValidateEgress(t *testing.T) {
	cases := []struct {
		name    string
		egress  *EgressSpec
		wantErr string
	}{
		{"nil", nil, ""},
		{"block only", &EgressSpec{BlockPrivateRanges: true}, ""},
		{"both proxies", &EgressSpec{Proxy: &EgressProxySpec{HTTPProxy: "http://p:3128", HTTPSProxy: "https://p:3129", NoProxy: ".svc"}}, ""},
		{"https only", &EgressSpec{Proxy: &EgressProxySpec{HTTPSProxy: "http://[fd00::1]:3128"}}, ""},
		{"no proxy url", &EgressSpec{Proxy: &EgressProxySpec{NoProxy: ".svc"}}, "set httpProxy, httpsProxy or both"},
		{"credentials", &EgressSpec{Proxy: &EgressProxySpec{HTTPSProxy: "http://user:pass@p:3128"}}, "must not carry credentials"},
		{"bad scheme", &EgressSpec{Proxy: &EgressProxySpec{HTTPProxy: "socks5://p:1080"}}, "scheme must be http or https"},
		{"no host", &EgressSpec{Proxy: &EgressProxySpec{HTTPProxy: "http://:3128"}}, "missing host"},
		{"unparseable", &EgressSpec{Proxy: &EgressProxySpec{HTTPSProxy: "http://p:bad port"}}, "spec.egress.proxy.httpsProxy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateEgress(tc.egress)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
