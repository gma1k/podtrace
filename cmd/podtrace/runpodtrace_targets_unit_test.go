package main

import (
	"strings"
	"testing"

	"github.com/podtrace/podtrace/internal/ebpf"
	"github.com/podtrace/podtrace/internal/kubernetes"
)

func TestRunPodtrace_PreResolvedNoneResolvable(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()
	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return &mockPodResolver{}, nil
	}
	preresolvedPods = []string{
		"ns/pod/abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789/main",
	}

	err := runPodtraceUntilDone(t, cmdWithNamespaceChanged())
	if err == nil || !strings.Contains(err.Error(), "no pre-resolved targets resolvable on this node") {
		t.Fatalf("expected pre-resolved-unresolvable error, got %v", err)
	}
}

func TestRunPodtrace_DynamicTargetsZeroPods(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()
	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return &mockPodResolverWithClientset{}, nil
	}
	tracerFactory = func() (ebpf.TracerInterface, error) {
		return &mockTracer{}, nil
	}
	podSelector = "app=x"

	err := runPodtraceUntilDone(t, cmdWithNamespaceChanged())
	if err == nil || !strings.Contains(err.Error(), "target selection matched zero running pods") {
		t.Fatalf("expected zero-running-pods error, got %v", err)
	}
}
