package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/gma1k/podtrace/internal/ebpf"
	"github.com/gma1k/podtrace/internal/kubernetes"
	"github.com/gma1k/podtrace/internal/status"
)

var realStatusClusterFactory func(statusOptions) (status.Cluster, error)

func TestMain(m *testing.M) {
	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return nil, fmt.Errorf("test: resolverFactory not stubbed (refusing to contact a live cluster)")
	}
	tracerFactory = func() (ebpf.TracerInterface, error) {
		return nil, fmt.Errorf("test: tracerFactory not stubbed")
	}
	realStatusClusterFactory = statusClusterFactory
	statusClusterFactory = func(statusOptions) (status.Cluster, error) {
		return nil, fmt.Errorf("test: statusClusterFactory not stubbed (refusing to contact a live cluster)")
	}
	os.Exit(m.Run())
}
