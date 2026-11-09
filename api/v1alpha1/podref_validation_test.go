package v1alpha1

import (
	"strings"
	"testing"
)

func TestValidatePodRef(t *testing.T) {
	cases := []struct {
		name    string
		ref     PodRef
		wantErr string
	}{
		{"plain", PodRef{Name: "api-7d9f"}, ""},
		{"dotted static pod", PodRef{Namespace: "kube-system", Name: "etcd-ip-10-0-1-2.ec2.internal"}, ""},
		{"long subdomain", PodRef{Name: strings.Repeat("a", 63) + "." + strings.Repeat("b", 63)}, ""},
		{"comma smuggles a ref", PodRef{Name: "x,victim/db-0"}, "podRef name"},
		{"slash", PodRef{Name: "victim/db-0"}, "podRef name"},
		{"empty name", PodRef{}, "podRef name"},
		{"uppercase", PodRef{Name: "API"}, "podRef name"},
		{"too long", PodRef{Name: strings.Repeat("a", 254)}, "podRef name"},
		{"namespace with dot", PodRef{Namespace: "a.b", Name: "p"}, "podRef namespace"},
		{"namespace with comma", PodRef{Namespace: "a,b", Name: "p"}, "podRef namespace"},
		{"namespace too long", PodRef{Namespace: strings.Repeat("n", 64), Name: "p"}, "podRef namespace"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePodRef(tc.ref)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidatePodRef(%+v) = %v, want nil", tc.ref, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ValidatePodRef(%+v) = %v, want %q", tc.ref, err, tc.wantErr)
			}
		})
	}
}

func TestValidatePodRefsNamesTheOffendingIndex(t *testing.T) {
	if err := ValidatePodRefs("spec.podRefs", []PodRef{{Name: "ok"}}); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	err := ValidatePodRefs("spec.podRefs", []PodRef{{Name: "ok"}, {Name: "a,b"}})
	if err == nil || !strings.Contains(err.Error(), "spec.podRefs[1]") {
		t.Fatalf("err = %v, want spec.podRefs[1]", err)
	}
}
