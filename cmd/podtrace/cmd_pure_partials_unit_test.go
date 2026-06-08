package main

import (
	"strings"
	"testing"
)

func TestBuildApplicationTrace_Errors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*watchOptions)
		wantSub string
	}{
		{
			name:    "no target",
			mutate:  func(o *watchOptions) {},
			wantSub: "one of --app or --label",
		},
		{
			name:    "empty exporter",
			mutate:  func(o *watchOptions) { o.AppName = "shop"; o.Exporter = "" },
			wantSub: "--exporter must not be empty",
		},
		{
			name:    "label without name",
			mutate:  func(o *watchOptions) { o.Labels = []string{"app=api"} },
			wantSub: "--name is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := baseWatchOpts()
			tt.mutate(&opts)
			_, err := buildApplicationTrace(opts)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantSub)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.wantSub)
			}
		})
	}
}

func TestCollectEnvReport_CRIEndpointEnv(t *testing.T) {
	const want = "unix:///run/test-cri.sock"
	t.Setenv("PODTRACE_CRI_ENDPOINT", want)

	rep := collectEnvReport()
	if rep.CRIEndpointEnv != want {
		t.Fatalf("CRIEndpointEnv = %q, want %q", rep.CRIEndpointEnv, want)
	}
}

func TestCollectEnvReport_CRIEndpointEnvUnset(t *testing.T) {
	t.Setenv("PODTRACE_CRI_ENDPOINT", "")

	rep := collectEnvReport()
	if rep.CRIEndpointEnv != "" {
		t.Fatalf("CRIEndpointEnv = %q, want empty", rep.CRIEndpointEnv)
	}
}
