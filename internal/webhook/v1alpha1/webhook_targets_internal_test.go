package v1alpha1

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func TestValidatePodTraceTargets_ExactlyOne(t *testing.T) {
	sel := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}}
	refs := []podtracev1alpha1.PodRef{{Name: "p"}}
	app := &podtracev1alpha1.AppSelector{MatchSelectors: []metav1.LabelSelector{{MatchLabels: map[string]string{"tier": "web"}}}}

	tests := []struct {
		name    string
		sel     *metav1.LabelSelector
		refs    []podtracev1alpha1.PodRef
		app     *podtracev1alpha1.AppSelector
		wantErr string // "" => valid
	}{
		{"none", nil, nil, nil, "must be set"},
		{"selector only", sel, nil, nil, ""},
		{"podRefs only", nil, refs, nil, ""},
		{"appSelector only", nil, nil, app, ""},
		{"selector+podRefs", sel, refs, nil, "mutually exclusive"},
		{"selector+appSelector", sel, nil, app, "mutually exclusive"},
		{"podRefs+appSelector", nil, refs, app, "mutually exclusive"},
		{"all three", sel, refs, app, "mutually exclusive"},
		{"empty selector counts as unset", &metav1.LabelSelector{}, nil, app, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePodTraceTargets(tt.sel, tt.refs, tt.app)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
