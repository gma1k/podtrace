package nodespawn

import "testing"

func TestHasTagOrDigest_DirectCases(t *testing.T) {
	cases := []struct {
		ref  string
		want bool
	}{
		{"podtrace", false},
		{"podtrace:v1", true},
		{"ghcr.io/gma1k/podtrace", false},
		{"ghcr.io/gma1k/podtrace:1.2.3", true},
		{"registry:5000/podtrace", false},
		{"registry:5000/podtrace:v1", true},
		{"ghcr.io/gma1k/podtrace@sha256:abcd", true},
		{"img@sha256:deadbeef", true},
	}
	for _, tc := range cases {
		t.Run(tc.ref, func(t *testing.T) {
			if got := hasTagOrDigest(tc.ref); got != tc.want {
				t.Errorf("hasTagOrDigest(%q) = %v, want %v", tc.ref, got, tc.want)
			}
		})
	}
}
