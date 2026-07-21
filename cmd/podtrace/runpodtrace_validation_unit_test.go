package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/podtrace/podtrace/internal/kubernetes"
)

func TestRunPodtrace_TracingSampleRateFlagError(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()

	origRate := tracingSampleRate
	t.Cleanup(func() { tracingSampleRate = origRate })

	cmd := &cobra.Command{}
	cmd.Flags().Float64Var(&tracingSampleRate, "tracing-sample-rate", 0, "")
	if err := cmd.Flags().Set("tracing-sample-rate", "2.0"); err != nil {
		t.Fatal(err)
	}
	enableTracing = true

	err := runPodtrace(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "--tracing-sample-rate must be between") {
		t.Fatalf("expected tracing-sample-rate error, got %v", err)
	}
}

func TestRunPodtrace_InvalidNamespaceDeterministic(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()
	namespace = "Bad_NS"

	err := runPodtrace(cmdWithNamespaceChanged(), []string{"test-pod"})
	if err == nil || !strings.Contains(err.Error(), "invalid namespace") {
		t.Fatalf("expected invalid namespace error, got %v", err)
	}
}

func TestRunPodtrace_InvalidNamespacesCSV(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()
	namespacesCSV = "Bad_NS"

	err := runPodtrace(cmdWithNamespaceChanged(), []string{"test-pod"})
	if err == nil || !strings.Contains(err.Error(), "invalid namespace in --namespaces") {
		t.Fatalf("expected invalid --namespaces error, got %v", err)
	}
}

func TestRunPodtrace_InvalidDiagnoseDuration(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()
	diagnoseDuration = "not-a-duration"

	err := runPodtrace(cmdWithNamespaceChanged(), []string{"test-pod"})
	if err == nil || !strings.Contains(err.Error(), "invalid --diagnose duration") {
		t.Fatalf("expected invalid diagnose-duration error, got %v", err)
	}
}

func TestRunPodtrace_WatchAllNamespacesZeroResolved(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()

	origWatchAll := watchAllNamespaces
	t.Cleanup(func() { watchAllNamespaces = origWatchAll })
	watchAllNamespaces = true
	podSelector = "app=x"
	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return &mockPodResolver{}, nil
	}

	err := runPodtrace(cmdWithNamespaceChanged(), nil)
	if err == nil || !strings.Contains(err.Error(), "target selection resolved zero pods") {
		t.Fatalf("expected zero-resolved-pods error, got %v", err)
	}
}

func TestRunPodtrace_PreResolvedParseError(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()
	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return &mockPodResolver{}, nil
	}

	preresolvedPods = []string{"bad"}

	err := runPodtrace(cmdWithNamespaceChanged(), nil)
	if err == nil || !strings.Contains(err.Error(), "preresolved ref") {
		t.Fatalf("expected preresolved parse error, got %v", err)
	}
}
