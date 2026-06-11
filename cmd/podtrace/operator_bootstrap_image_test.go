package main

import (
	"testing"

	"github.com/podtrace/podtrace/internal/config"
)

// TestBootstrapFallbackImage is a regression test for OLM installs coming up
// with no agent DaemonSet: the CSV forgot PODTRACE_BOOTSTRAP_IMAGE and the
// operator never set BootstrapFallbackImage, so the TracerConfig bootstrap
// silently skipped itself.
func TestBootstrapFallbackImage(t *testing.T) {
	savedImage, savedVersion := config.Image, config.Version
	defer func() { config.Image, config.Version = savedImage, savedVersion }()

	cases := []struct {
		name    string
		image   string
		version string
		want    string
	}{
		{"clean release with v prefix", "ghcr.io/gma1k/podtrace", "v0.12.9", "ghcr.io/gma1k/podtrace:0.12.9"},
		{"clean release without prefix", "ghcr.io/gma1k/podtrace", "0.12.9", "ghcr.io/gma1k/podtrace:0.12.9"},
		{"dev build", "ghcr.io/gma1k/podtrace", "dev", ""},
		{"dirty build", "ghcr.io/gma1k/podtrace", "v0.12.9-2-gfdec2a4-dirty", ""},
		{"no image baked in", "", "v0.12.9", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config.Image, config.Version = tc.image, tc.version
			if got := bootstrapFallbackImage(); got != tc.want {
				t.Errorf("bootstrapFallbackImage() = %q, want %q", got, tc.want)
			}
		})
	}
}