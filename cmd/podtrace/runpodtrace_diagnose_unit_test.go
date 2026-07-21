package main

import (
	"context"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/ebpf"
	"github.com/podtrace/podtrace/internal/events"
	"github.com/podtrace/podtrace/internal/kubernetes"
	"github.com/podtrace/podtrace/internal/system"
)

func runPodtraceUntilDone(t *testing.T, cmd *cobra.Command) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- runPodtrace(cmd, []string{"test-pod"}) }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("runPodtrace did not complete within 5s")
		return nil
	}
}

func TestRunPodtrace_DiagnoseCompletesBasic(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()

	t.Setenv("PODTRACE_ALLOW_BROAD_CGROUP", "1")
	t.Setenv(system.EnvSkipLockdownCheck, "1")
	t.Setenv("PODTRACE_K8S_ENRICHMENT_ENABLED", "false")

	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return &mockPodResolver{}, nil
	}
	tracerFactory = func() (ebpf.TracerInterface, error) {
		return &mockTracer{}, nil
	}
	diagnoseDuration = "50ms"

	if err := runPodtraceUntilDone(t, cmdWithNamespaceChanged()); err != nil {
		t.Fatalf("expected diagnose completion, got %v", err)
	}
}

func TestRunPodtrace_DiagnoseWithAuxiliaryConsumers(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()
	t.Setenv("PODTRACE_ALLOW_BROAD_CGROUP", "1")
	t.Setenv(system.EnvSkipLockdownCheck, "1")
	t.Setenv("PODTRACE_K8S_ENRICHMENT_ENABLED", "true")

	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return &mockPodResolverWithClientset{}, nil
	}
	tracerFactory = func() (ebpf.TracerInterface, error) {
		return &mockTracer{}, nil
	}
	enableMetrics = true
	enableTracing = true
	eventFilter = "dns,net"
	diagnoseDuration = "50ms"

	if err := runPodtraceUntilDone(t, cmdWithNamespaceChanged()); err != nil {
		t.Fatalf("expected diagnose completion with auxiliary consumers, got %v", err)
	}
}

func TestRunPodtrace_DiagnoseAttachError(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()
	t.Setenv("PODTRACE_ALLOW_BROAD_CGROUP", "1")
	t.Setenv(system.EnvSkipLockdownCheck, "1")
	t.Setenv("PODTRACE_K8S_ENRICHMENT_ENABLED", "false")

	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return &mockPodResolver{}, nil
	}
	tracerFactory = func() (ebpf.TracerInterface, error) {
		return &mockTracer{attachToCgroupFunc: func(string) error {
			return errAttach
		}}, nil
	}
	diagnoseDuration = "50ms"

	err := runPodtraceUntilDone(t, cmdWithNamespaceChanged())
	if err == nil {
		t.Fatal("expected attach error to surface")
	}
}

var errAttach = &attachTestError{}

type attachTestError struct{}

func (*attachTestError) Error() string { return "attach failed (test)" }

func TestRunPodtrace_DiagnoseStartError(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()
	t.Setenv("PODTRACE_ALLOW_BROAD_CGROUP", "1")
	t.Setenv(system.EnvSkipLockdownCheck, "1")
	t.Setenv("PODTRACE_K8S_ENRICHMENT_ENABLED", "false")

	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return &mockPodResolver{}, nil
	}
	tracerFactory = func() (ebpf.TracerInterface, error) {
		return &mockTracer{startFunc: func(context.Context, chan<- *events.Event) error {
			return errAttach
		}}, nil
	}
	diagnoseDuration = "50ms"

	err := runPodtraceUntilDone(t, cmdWithNamespaceChanged())
	if err == nil {
		t.Fatal("expected tracer.Start error to surface")
	}
}

type podIPResolver struct{}

func (podIPResolver) ResolvePod(_ context.Context, podName, namespace, containerName string) (*kubernetes.PodInfo, error) {
	return &kubernetes.PodInfo{
		PodName:       podName,
		Namespace:     namespace,
		ContainerID:   "test-container-id",
		CgroupPath:    "/sys/fs/cgroup/test",
		ContainerName: containerName,
		PodIP:         "127.0.0.1",
	}, nil
}

func TestRunPodtrace_DiagnoseProfilingSingleTarget(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()
	t.Setenv("PODTRACE_ALLOW_BROAD_CGROUP", "1")
	t.Setenv(system.EnvSkipLockdownCheck, "1")
	t.Setenv("PODTRACE_K8S_ENRICHMENT_ENABLED", "false")

	origProfilingEnabled := config.ProfilingEnabled
	t.Cleanup(func() { config.ProfilingEnabled = origProfilingEnabled })

	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return &podIPResolver{}, nil
	}
	tracerFactory = func() (ebpf.TracerInterface, error) {
		return &mockTracer{}, nil
	}
	enableProfiling = true
	podsCSV = "p1"
	diagnoseDuration = "80ms"

	if err := runPodtraceUntilDone(t, cmdWithNamespaceChanged()); err != nil {
		t.Fatalf("expected diagnose completion with single-target profiling, got %v", err)
	}
}

func TestRunPodtrace_DiagnoseProfilingMultiTarget(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()
	t.Setenv("PODTRACE_ALLOW_BROAD_CGROUP", "1")
	t.Setenv(system.EnvSkipLockdownCheck, "1")
	t.Setenv("PODTRACE_K8S_ENRICHMENT_ENABLED", "false")

	origProfilingEnabled := config.ProfilingEnabled
	t.Cleanup(func() { config.ProfilingEnabled = origProfilingEnabled })

	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return &podIPResolver{}, nil
	}
	tracerFactory = func() (ebpf.TracerInterface, error) {
		return &mockTracer{}, nil
	}
	enableProfiling = true
	podsCSV = "p1,p2"
	diagnoseDuration = "80ms"

	if err := runPodtraceUntilDone(t, cmdWithNamespaceChanged()); err != nil {
		t.Fatalf("expected diagnose completion with multi-target profiling, got %v", err)
	}
}

func TestRunPodtrace_DiagnoseProfilingNoPodIP(t *testing.T) {
	saveRunPodtraceGlobals(t)
	resetRunPodtraceGlobals()
	t.Setenv("PODTRACE_ALLOW_BROAD_CGROUP", "1")
	t.Setenv(system.EnvSkipLockdownCheck, "1")
	t.Setenv("PODTRACE_K8S_ENRICHMENT_ENABLED", "false")

	origProfilingEnabled := config.ProfilingEnabled
	t.Cleanup(func() { config.ProfilingEnabled = origProfilingEnabled })

	resolverFactory = func() (kubernetes.PodResolverInterface, error) {
		return &mockPodResolver{}, nil
	}
	tracerFactory = func() (ebpf.TracerInterface, error) {
		return &mockTracer{}, nil
	}
	enableProfiling = true
	diagnoseDuration = "50ms"

	if err := runPodtraceUntilDone(t, cmdWithNamespaceChanged()); err != nil {
		t.Fatalf("expected diagnose completion with profiling-but-no-IP, got %v", err)
	}
}
