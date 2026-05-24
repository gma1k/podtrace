package nodespawn

import (
	"testing"

	"github.com/podtrace/podtrace/internal/config"
)

func TestResolveImage(t *testing.T) {
	originalImage := config.Image
	t.Cleanup(func() { config.Image = originalImage })

	tests := []struct {
		name      string
		linkerVal string
		envVal    string
		opts      ResolveImageOptions
		want      string
		wantWarn  bool
	}{
		{
			name:      "override wins over env and linker",
			linkerVal: "ghcr.io/gma1k/podtrace",
			envVal:    "env.example/podtrace:env",
			opts:      ResolveImageOptions{Override: "flag.example/podtrace:flag", Version: "v1.2.3"},
			want:      "flag.example/podtrace:flag",
		},
		{
			name:      "env wins over linker default",
			linkerVal: "ghcr.io/gma1k/podtrace",
			envVal:    "env.example/podtrace:env",
			opts:      ResolveImageOptions{Version: "v1.2.3"},
			want:      "env.example/podtrace:env",
		},
		{
			name:      "linker default + released version",
			linkerVal: "ghcr.io/gma1k/podtrace",
			opts:      ResolveImageOptions{Version: "v1.2.3"},
			want:      "ghcr.io/gma1k/podtrace:v1.2.3",
		},
		{
			name:      "dev version falls back to latest with warn",
			linkerVal: "ghcr.io/gma1k/podtrace",
			opts:      ResolveImageOptions{Version: "dev"},
			want:      "ghcr.io/gma1k/podtrace:latest",
			wantWarn:  true,
		},
		{
			name:      "dev-sha version falls back to latest with warn",
			linkerVal: "ghcr.io/gma1k/podtrace",
			opts:      ResolveImageOptions{Version: "dev-a7e4dc2"},
			want:      "ghcr.io/gma1k/podtrace:latest",
			wantWarn:  true,
		},
		{
			name: "empty linker falls back to project default",
			opts: ResolveImageOptions{Version: "v1.0.0"},
			want: "ghcr.io/gma1k/podtrace:v1.0.0",
		},
		{
			name:      "empty version yields latest tag without warn (non-dev)",
			linkerVal: "ghcr.io/gma1k/podtrace",
			opts:      ResolveImageOptions{},
			want:      "ghcr.io/gma1k/podtrace:latest",
		},
		{
			name:      "whitespace in override is trimmed and treated as set",
			linkerVal: "ghcr.io/gma1k/podtrace",
			opts:      ResolveImageOptions{Override: "  flag.example/podtrace:flag  ", Version: "v1.2.3"},
			want:      "flag.example/podtrace:flag",
		},
		{
			name:      "whitespace-only override is treated as unset and yields env",
			linkerVal: "ghcr.io/gma1k/podtrace",
			envVal:    "env.example/podtrace:env",
			opts:      ResolveImageOptions{Override: "   ", Version: "v1.2.3"},
			want:      "env.example/podtrace:env",
		},
		{
			name:      "linker default with tag baked in is used verbatim (no version suffix)",
			linkerVal: "10.5.0.1:5000/podtrace:dev5",
			opts:      ResolveImageOptions{Version: "dev"},
			want:      "10.5.0.1:5000/podtrace:dev5",
		},
		{
			name:      "linker default with port and tag is parsed correctly",
			linkerVal: "registry.example.com:5000/podtrace:v1.0",
			opts:      ResolveImageOptions{Version: "v9.9"},
			want:      "registry.example.com:5000/podtrace:v1.0",
		},
		{
			name:      "linker default with digest is used verbatim",
			linkerVal: "ghcr.io/gma1k/podtrace@sha256:abc",
			opts:      ResolveImageOptions{Version: "v1.0"},
			want:      "ghcr.io/gma1k/podtrace@sha256:abc",
		},
		{
			name:      "git-describe dirty version falls back to latest with warn",
			linkerVal: "ghcr.io/gma1k/podtrace",
			opts:      ResolveImageOptions{Version: "v0.11.11-14-g8ff3976-dirty"},
			want:      "ghcr.io/gma1k/podtrace:latest",
			wantWarn:  true,
		},
		{
			name:      "git-describe post-tag version falls back to latest with warn",
			linkerVal: "ghcr.io/gma1k/podtrace",
			opts:      ResolveImageOptions{Version: "v0.11.11-14-g8ff3976"},
			want:      "ghcr.io/gma1k/podtrace:latest",
			wantWarn:  true,
		},
		{
			name:      "clean release tag used verbatim",
			linkerVal: "ghcr.io/gma1k/podtrace",
			opts:      ResolveImageOptions{Version: "v0.11.12"},
			want:      "ghcr.io/gma1k/podtrace:v0.11.12",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config.Image = tc.linkerVal
			t.Setenv("PODTRACE_IMAGE", tc.envVal)

			got, warn := ResolveImage(tc.opts)
			if got != tc.want {
				t.Errorf("image = %q, want %q", got, tc.want)
			}
			if warn != tc.wantWarn {
				t.Errorf("warn = %v, want %v", warn, tc.wantWarn)
			}
		})
	}
}
