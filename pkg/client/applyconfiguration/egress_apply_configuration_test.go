package applyconfiguration_test

import (
	"encoding/json"
	"reflect"
	"testing"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	"github.com/gma1k/podtrace/pkg/client/applyconfiguration"
	applyv1alpha1 "github.com/gma1k/podtrace/pkg/client/applyconfiguration/api/v1alpha1"
)

func TestAnEgressApplyConfigurationRoundTripsIntoTheAPIType(t *testing.T) {
	spec := applyv1alpha1.TracerConfigSpec().
		WithEgress(applyv1alpha1.EgressSpec().
			WithBlockPrivateRanges(true).
			WithProxy(applyv1alpha1.EgressProxySpec().
				WithHTTPProxy("http://proxy:3128").
				WithHTTPSProxy("http://proxy:3129").
				WithNoProxy(".svc")))

	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	var got podtracev1alpha1.TracerConfigSpec
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	want := &podtracev1alpha1.EgressSpec{
		BlockPrivateRanges: true,
		Proxy: &podtracev1alpha1.EgressProxySpec{
			HTTPProxy:  "http://proxy:3128",
			HTTPSProxy: "http://proxy:3129",
			NoProxy:    ".svc",
		},
	}
	if !reflect.DeepEqual(got.Egress, want) {
		t.Fatalf("egress = %+v, want %+v", got.Egress, want)
	}
}

func TestForKindKnowsTheEgressTypes(t *testing.T) {
	cases := map[string]any{
		"EgressSpec":      &applyv1alpha1.EgressSpecApplyConfiguration{},
		"EgressProxySpec": &applyv1alpha1.EgressProxySpecApplyConfiguration{},
	}
	for kind, want := range cases {
		got := applyconfiguration.ForKind(podtracev1alpha1.SchemeGroupVersion.WithKind(kind))
		if reflect.TypeOf(got) != reflect.TypeOf(want) {
			t.Errorf("ForKind(%s) = %T, want %T", kind, got, want)
		}
	}
}
