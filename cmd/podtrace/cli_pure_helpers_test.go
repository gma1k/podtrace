package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/spf13/cobra"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/kubernetes"
	"github.com/podtrace/podtrace/internal/kubernetes/nodespawn"
)

func TestFilterEvents_CryptoFilter(t *testing.T) {
	in := make(chan *events.Event, 3)
	out := make(chan *events.Event, 3)

	go func() {
		defer close(in)
		in <- &events.Event{Type: events.EventAFALG}
		in <- &events.Event{Type: events.EventConnect}
		in <- &events.Event{Type: events.EventAFALG}
	}()

	go filterEvents(context.Background(), in, out, "crypto")

	count := 0
	for ev := range out {
		if ev.Type != events.EventAFALG {
			t.Errorf("crypto filter passed a non-AFALG event: %v", ev.Type)
		}
		count++
	}
	if count != 2 {
		t.Errorf("expected 2 crypto events, got %d", count)
	}
}

func TestPodContainerTargets_NilReturnsNil(t *testing.T) {
	if got := podContainerTargets(nil); got != nil {
		t.Errorf("podContainerTargets(nil) = %v, want nil", got)
	}
}

func TestPodContainerTargets_UsesContainersList(t *testing.T) {
	p := &kubernetes.PodInfo{
		Containers: []kubernetes.ContainerTarget{
			{Name: "a", ID: "id-a", CgroupPath: "/cg/a"},
			{Name: "b", ID: "id-b", CgroupPath: "/cg/b"},
		},
	}
	got := podContainerTargets(p)
	if len(got) != 2 || got[0].Name != "a" || got[1].Name != "b" {
		t.Fatalf("expected the pod's Containers list verbatim, got %+v", got)
	}
}

func TestPodContainerTargets_FallsBackToSingularFields(t *testing.T) {
	p := &kubernetes.PodInfo{
		ContainerName: "solo",
		ContainerID:   "id-solo",
		CgroupPath:    "/cg/solo",
	}
	got := podContainerTargets(p)
	if len(got) != 1 {
		t.Fatalf("expected a single synthesized target, got %d", len(got))
	}
	if got[0].Name != "solo" || got[0].ID != "id-solo" || got[0].CgroupPath != "/cg/solo" {
		t.Fatalf("synthesized target lost the singular fields: %+v", got[0])
	}
}

func TestApplyTracingFlags_JaegerSplunkSynthesize(t *testing.T) {
	restoreTracingFlagGlobals(t)
	origSynthesizeFlag := enableSynthesizeSpans
	origSynthesizeConfig := config.SynthesizeSpans
	t.Cleanup(func() {
		enableSynthesizeSpans = origSynthesizeFlag
		config.SynthesizeSpans = origSynthesizeConfig
	})
	defer resetTracingConfig()

	cmd := &cobra.Command{}
	cmd.Flags().BoolVar(&enableTracing, "tracing", false, "")
	cmd.Flags().StringVar(&tracingJaegerEndpoint, "tracing-jaeger-endpoint", "", "")
	cmd.Flags().StringVar(&tracingSplunkEndpoint, "tracing-splunk-endpoint", "", "")
	cmd.Flags().StringVar(&tracingSplunkToken, "tracing-splunk-token", "", "")
	cmd.Flags().BoolVar(&enableSynthesizeSpans, "tracing-synthesize-spans", false, "")

	for flag, value := range map[string]string{
		"tracing":                  "true",
		"tracing-jaeger-endpoint":  "jaeger:4318",
		"tracing-splunk-endpoint":  "splunk:8088",
		"tracing-splunk-token":     "hec-token",
		"tracing-synthesize-spans": "true",
	} {
		if err := cmd.Flags().Set(flag, value); err != nil {
			t.Fatalf("set %s: %v", flag, err)
		}
	}

	if err := applyTracingFlags(cmd); err != nil {
		t.Fatalf("applyTracingFlags: %v", err)
	}
	if !config.TracingEnabled {
		t.Error("TracingEnabled not set")
	}
	if config.JaegerEndpoint != "jaeger:4318" {
		t.Errorf("JaegerEndpoint=%q, want jaeger:4318", config.JaegerEndpoint)
	}
	if config.SplunkEndpoint != "splunk:8088" {
		t.Errorf("SplunkEndpoint=%q, want splunk:8088", config.SplunkEndpoint)
	}
	if config.SplunkToken != "hec-token" {
		t.Errorf("SplunkToken=%q, want hec-token", config.SplunkToken)
	}
	if !config.SynthesizeSpans {
		t.Error("SynthesizeSpans not set by --tracing-synthesize-spans")
	}
}

type unwrapToNilError struct{}

func (unwrapToNilError) Error() string { return "unwrap-nil" }
func (unwrapToNilError) Unwrap() error { return nil }

func TestErrorsAs_UnwrapChainEndsAtNil(t *testing.T) {
	var target *nodespawn.ExitError
	if errorsAs(unwrapToNilError{}, &target) {
		t.Fatal("errorsAs must return false when the chain unwraps to nil without matching")
	}
	if target != nil {
		t.Fatalf("target must stay nil, got %#v", target)
	}
}

func TestErrorsAs_DeepWrappedExitError(t *testing.T) {
	base := &nodespawn.ExitError{Code: 3, Node: "n"}
	chain := fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", base))

	var target *nodespawn.ExitError
	if !errorsAs(chain, &target) {
		t.Fatal("errorsAs must find an ExitError two levels deep")
	}
	if target == nil || target.Code != 3 {
		t.Fatalf("unexpected unwrapped target: %#v", target)
	}
}
