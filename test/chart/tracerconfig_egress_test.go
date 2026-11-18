package chart_test

import (
	"reflect"
	"strings"
	"testing"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestTheChartLeavesEgressUnsetByDefault(t *testing.T) {
	if tc := renderedTracerConfig(t); tc.Spec.Egress != nil {
		t.Fatalf("default chart rendered spec.egress = %+v", tc.Spec.Egress)
	}
}

func TestEgressValuesReachTheTracerConfig(t *testing.T) {
	tc := renderedTracerConfig(t,
		"tracerConfig.egress.blockPrivateRanges=true",
		"tracerConfig.egress.proxy.httpProxy=http://proxy.corp:3128",
		"tracerConfig.egress.proxy.httpsProxy=http://proxy.corp:3129",
		`tracerConfig.egress.proxy.noProxy=.svc\,10.0.0.0/8`,
	)
	want := &podtracev1alpha1.EgressSpec{
		BlockPrivateRanges: true,
		Proxy: &podtracev1alpha1.EgressProxySpec{
			HTTPProxy:  "http://proxy.corp:3128",
			HTTPSProxy: "http://proxy.corp:3129",
			NoProxy:    ".svc,10.0.0.0/8",
		},
	}
	if !reflect.DeepEqual(tc.Spec.Egress, want) {
		t.Fatalf("spec.egress = %+v, want %+v", tc.Spec.Egress, want)
	}
	if err := podtracev1alpha1.ValidateEgress(tc.Spec.Egress); err != nil {
		t.Fatalf("rendered egress fails admission: %v", err)
	}
}

func TestBlockingPrivateRangesAloneRendersNoProxy(t *testing.T) {
	tc := renderedTracerConfig(t, "tracerConfig.egress.blockPrivateRanges=true")
	if tc.Spec.Egress == nil || !tc.Spec.Egress.BlockPrivateRanges || tc.Spec.Egress.Proxy != nil {
		t.Fatalf("spec.egress = %+v", tc.Spec.Egress)
	}
}

func TestTheValuesSchemaRejectsAProxyWithCredentials(t *testing.T) {
	out, err := helmTemplate(t, "--set", "tracerConfig.egress.proxy.httpsProxy=http://user:pass@proxy:3128")
	if err == nil {
		t.Fatalf("a proxy URL with credentials rendered:\n%s", out)
	}
	if !strings.Contains(err.Error()+string(out), "httpsProxy") {
		t.Fatalf("error does not name the field: %v", err)
	}
}
