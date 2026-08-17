package v1alpha1

import (
	"strings"
	"testing"
)

func TestValidateSessionTemplateMetadata(t *testing.T) {
	longKey := strings.Repeat("a", 64)
	cases := []struct {
		name    string
		meta    PodTraceSessionTemplateMetadata
		wantErr string
	}{
		{
			name: "valid labels and annotations",
			meta: PodTraceSessionTemplateMetadata{
				Labels:      map[string]string{"team": "obs", "app.kubernetes.io/name": "podtrace"},
				Annotations: map[string]string{"note": "scheduled"},
			},
		},
		{
			name: "empty is valid",
			meta: PodTraceSessionTemplateMetadata{},
		},
		{
			name:    "label key too long",
			meta:    PodTraceSessionTemplateMetadata{Labels: map[string]string{longKey: "v"}},
			wantErr: "labels",
		},
		{
			name:    "label value invalid",
			meta:    PodTraceSessionTemplateMetadata{Labels: map[string]string{"team": "not a valid value"}},
			wantErr: "labels",
		},
		{
			name:    "annotation key invalid",
			meta:    PodTraceSessionTemplateMetadata{Annotations: map[string]string{"bad key": "v"}},
			wantErr: "annotations",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSessionTemplateMetadata(tc.meta)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateSessionTemplateMetadata() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateSessionTemplateMetadata() = nil, want error mentioning %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want it to mention %q", err.Error(), tc.wantErr)
			}
		})
	}
}
