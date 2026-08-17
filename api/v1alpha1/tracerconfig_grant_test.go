package v1alpha1

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestTracerConfigAllowsSessionFrom(t *testing.T) {
	const operatorDefault = "podtrace-system"
	tc := func(systemNamespace, grant string) *TracerConfig {
		obj := &TracerConfig{Spec: TracerConfigSpec{SystemNamespace: systemNamespace}}
		if grant != "-" {
			obj.Annotations = map[string]string{AllowSessionsFromAnnotation: grant}
		}
		return obj
	}

	cases := []struct {
		name   string
		config *TracerConfig
		source string
		want   bool
	}{
		{"NilConfigDenies", nil, "team-a", false},
		{"EmptySourceDenies", tc("fleet-b", "*"), "", false},
		{"OwnNamespaceAllowed", tc("team-a", "-"), "team-a", true},
		{"OperatorDefaultAllowed", tc(operatorDefault, "-"), "team-a", true},
		{"EmptySystemNamespaceUsesDefault", tc("", "-"), "team-a", true},
		{"CrossTenantNoGrantDenies", tc("fleet-b", "-"), "team-a", false},
		{"CrossTenantEmptyGrantDenies", tc("fleet-b", ""), "team-a", false},
		{"CrossTenantWildcardAllows", tc("fleet-b", "*"), "team-a", true},
		{"CrossTenantExactAllows", tc("fleet-b", "team-a"), "team-a", true},
		{"CrossTenantListAllows", tc("fleet-b", "ops,team-a,audit"), "team-a", true},
		{"CrossTenantNonMemberDenies", tc("fleet-b", "ops,audit"), "team-a", false},
		{"CrossTenantPrefixIsNotAMatch", tc("fleet-b", "team-a-2"), "team-a", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := TracerConfigAllowsSessionFrom(tc.config, tc.source, operatorDefault); got != tc.want {
				t.Errorf("TracerConfigAllowsSessionFrom(%v, %q) = %v, want %v", tc.config, tc.source, got, tc.want)
			}
		})
	}
}

func TestTracerConfigAllowsSessionFrom_IgnoresUnrelatedAnnotation(t *testing.T) {
	config := &TracerConfig{
		ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"unrelated": "team-a"}},
		Spec:       TracerConfigSpec{SystemNamespace: "fleet-b"},
	}
	if TracerConfigAllowsSessionFrom(config, "team-a", "podtrace-system") {
		t.Fatal("an unrelated annotation must not grant a cross-tenant pin")
	}
}
