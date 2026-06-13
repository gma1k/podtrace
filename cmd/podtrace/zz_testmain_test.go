package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/podtrace/podtrace/internal/ebpf"
	"github.com/podtrace/podtrace/internal/kubernetes"
)

// TestMain installs fail-closed default factories so no test can ever
// reach a real cluster or attach a real tracer. Tests that exercise the
// resolve/trace paths override these explicitly; everything else (e.g.
// input-validation tests) must fail fast rather than fall through to
// kubernetes.NewPodResolver(), which would load the developer's kubeconfig
// and hit whatever cluster it points at.
func TestMain(m *testing.M) {
	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return nil, fmt.Errorf("test: resolverFactory not stubbed (refusing to contact a live cluster)")
	}
	tracerFactory = func() (ebpf.TracerInterface, error) {
		return nil, fmt.Errorf("test: tracerFactory not stubbed")
	}
	os.Exit(m.Run())
}
