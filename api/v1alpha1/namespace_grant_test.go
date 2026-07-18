package v1alpha1

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNamespaceAllowsTracingFrom(t *testing.T) {
	ns := func(name, grant string) *corev1.Namespace {
		obj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
		if grant != "-" {
			obj.Annotations = map[string]string{AllowTracingFromAnnotation: grant}
		}
		return obj
	}

	cases := []struct {
		name   string
		target *corev1.Namespace
		source string
		want   bool
	}{
		{"NilTargetDenies", nil, "observer", false},
		{"EmptySourceDenies", ns("team-b", "*"), "", false},
		{"OwnNamespaceAlwaysAllowed", ns("team-a", "-"), "team-a", true},
		{"MissingAnnotationDenies", ns("team-b", "-"), "observer", false},
		{"EmptyAnnotationDenies", ns("team-b", ""), "observer", false},
		{"WhitespaceOnlyDenies", ns("team-b", " ,  , "), "observer", false},
		{"WildcardAllowsEveryone", ns("team-b", "*"), "observer", true},
		{"ExactMatchAllows", ns("team-b", "observer"), "observer", true},
		{"ListMembershipAllows", ns("team-b", "ops,observer,audit"), "observer", true},
		{"ListWithSpacesAllows", ns("team-b", " ops , observer "), "observer", true},
		{"NonMemberDenies", ns("team-b", "ops,audit"), "observer", false},
		{"PrefixIsNotAMatch", ns("team-b", "observer-2"), "observer", false},
		{"SubstringIsNotAMatch", ns("team-b", "the-observer-ns"), "observer", false},
		{"WildcardInsideListAllows", ns("team-b", "ops,*"), "observer", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NamespaceAllowsTracingFrom(tc.target, tc.source); got != tc.want {
				t.Errorf("NamespaceAllowsTracingFrom(%v, %q) = %v, want %v",
					tc.target, tc.source, got, tc.want)
			}
		})
	}
}
