package main

import (
	"testing"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/spf13/cobra"
)

func newTracingFlagsCommand() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableTracing, "tracing", config.DefaultTracingEnabled, "")
	cmd.Flags().StringVar(&tracingOTLPEndpoint, "tracing-otlp-endpoint", config.DefaultOTLPEndpoint, "")
	cmd.Flags().StringVar(&tracingJaegerEndpoint, "tracing-jaeger-endpoint", config.DefaultJaegerEndpoint, "")
	cmd.Flags().StringVar(&tracingSplunkEndpoint, "tracing-splunk-endpoint", config.DefaultSplunkEndpoint, "")
	cmd.Flags().StringVar(&tracingSplunkToken, "tracing-splunk-token", "", "")
	cmd.Flags().Float64Var(&tracingSampleRate, "tracing-sample-rate", config.DefaultTracingSampleRate, "")
	return cmd
}

func restoreTracingFlagGlobals(t *testing.T) {
	t.Helper()
	origEnable := enableTracing
	origOTLP := tracingOTLPEndpoint
	origJaeger := tracingJaegerEndpoint
	origSplunk := tracingSplunkEndpoint
	origToken := tracingSplunkToken
	origRate := tracingSampleRate
	t.Cleanup(func() {
		enableTracing = origEnable
		tracingOTLPEndpoint = origOTLP
		tracingJaegerEndpoint = origJaeger
		tracingSplunkEndpoint = origSplunk
		tracingSplunkToken = origToken
		tracingSampleRate = origRate
	})
}

func TestApplyTracingFlags_PreservesBundleConfig(t *testing.T) {
	restoreTracingFlagGlobals(t)
	defer resetTracingConfig()

	cmd := newTracingFlagsCommand()
	if err := cmd.Flags().Set("tracing", "true"); err != nil {
		t.Fatal(err)
	}

	config.OTLPEndpoint = "otel.observability:4318"
	config.TracingSampleRate = 0.25

	if err := applyTracingFlags(cmd); err != nil {
		t.Fatalf("applyTracingFlags: %v", err)
	}
	if !config.TracingEnabled {
		t.Error("TracingEnabled not set")
	}
	if config.OTLPEndpoint != "otel.observability:4318" {
		t.Errorf("bundle OTLP endpoint clobbered by flag default: %q", config.OTLPEndpoint)
	}
	if config.TracingSampleRate != 0.25 {
		t.Errorf("bundle sample rate clobbered by flag default: %v", config.TracingSampleRate)
	}
}

func TestApplyTracingFlags_ExplicitFlagsWin(t *testing.T) {
	restoreTracingFlagGlobals(t)
	defer resetTracingConfig()

	cmd := newTracingFlagsCommand()
	for flag, value := range map[string]string{
		"tracing":               "true",
		"tracing-otlp-endpoint": "cli-otel:4318",
		"tracing-sample-rate":   "0.5",
	} {
		if err := cmd.Flags().Set(flag, value); err != nil {
			t.Fatal(err)
		}
	}

	config.OTLPEndpoint = "bundle-otel:4318"
	config.TracingSampleRate = 0.25

	if err := applyTracingFlags(cmd); err != nil {
		t.Fatalf("applyTracingFlags: %v", err)
	}
	if config.OTLPEndpoint != "cli-otel:4318" {
		t.Errorf("explicit --tracing-otlp-endpoint not applied: %q", config.OTLPEndpoint)
	}
	if config.TracingSampleRate != 0.5 {
		t.Errorf("explicit --tracing-sample-rate not applied: %v", config.TracingSampleRate)
	}
}

func TestApplyTracingFlags_InvalidSampleRateErrors(t *testing.T) {
	restoreTracingFlagGlobals(t)
	defer resetTracingConfig()

	cmd := newTracingFlagsCommand()
	if err := cmd.Flags().Set("tracing", "true"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("tracing-sample-rate", "1.5"); err != nil {
		t.Fatal(err)
	}
	if err := applyTracingFlags(cmd); err == nil {
		t.Error("expected error for out-of-range --tracing-sample-rate")
	}
}

func TestApplyTracingFlags_DisabledIsNoOp(t *testing.T) {
	restoreTracingFlagGlobals(t)
	defer resetTracingConfig()

	cmd := newTracingFlagsCommand()
	config.TracingEnabled = false

	if err := applyTracingFlags(cmd); err != nil {
		t.Fatalf("applyTracingFlags: %v", err)
	}
	if config.TracingEnabled {
		t.Error("TracingEnabled set without --tracing")
	}
}
