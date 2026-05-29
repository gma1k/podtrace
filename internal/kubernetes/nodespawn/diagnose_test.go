package nodespawn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// shortDiagnoseTiming compresses the diagnose poll budget so tests stay fast.
func shortDiagnoseTiming(t *testing.T, timeout, interval time.Duration) {
	t.Helper()
	prevT, prevI := diagnoseStatusTimeout, diagnoseStatusPollInterval
	diagnoseStatusTimeout = timeout
	diagnoseStatusPollInterval = interval
	t.Cleanup(func() {
		diagnoseStatusTimeout = prevT
		diagnoseStatusPollInterval = prevI
	})
}

// stubDumpPodLogs replaces the package-level log fetcher for the duration of
// the test.
func stubDumpPodLogs(t *testing.T, fn func(context.Context, kubernetes.Interface, string, string) string) {
	t.Helper()
	prev := dumpPodLogs
	dumpPodLogs = fn
	t.Cleanup(func() { dumpPodLogs = prev })
}

func emptyLogs(_ context.Context, _ kubernetes.Interface, _, _ string) string { return "" }
func stubLogs(out string) func(context.Context, kubernetes.Interface, string, string) string {
	return func(_ context.Context, _ kubernetes.Interface, _, _ string) string { return out }
}

func TestDiagnoseAttachFailure_TerminatedPodWrapsWithExitCode(t *testing.T) {
	pod := terminatedSpawnPod("ns", "spawn", 1, "Error",
		"verifier rejected uretprobe_rd_kafka_consumer_poll: helper not supported")
	clientset := fake.NewSimpleClientset(pod)
	orig := errors.New("unable to upgrade connection: container podtrace not found in pod spawn_ns")

	err := diagnoseAttachFailure(context.Background(), clientset, "ns", "spawn", orig)

	var afe *AttachFailedError
	if !errors.As(err, &afe) {
		t.Fatalf("expected *AttachFailedError, got %T: %v", err, err)
	}
	if afe.ExitCode == nil || *afe.ExitCode != 1 {
		t.Errorf("ExitCode: got %v, want 1", afe.ExitCode)
	}
	if afe.Reason != "Error" {
		t.Errorf("Reason: got %q, want %q", afe.Reason, "Error")
	}
	if !strings.Contains(afe.Message, "uretprobe_rd_kafka_consumer_poll") {
		t.Errorf("Message did not propagate termination message: %q", afe.Message)
	}
	if !errors.Is(err, orig) {
		t.Errorf("Unwrap should expose the original attach error")
	}

	msg := afe.Error()
	for _, want := range []string{
		"exited with code 1",
		"uretprobe_rd_kafka_consumer_poll",
		"kubectl -n ns logs spawn",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("formatted error missing %q\n got: %s", want, msg)
		}
	}
}

// TestDiagnoseAttachFailure_RunningPodWithoutLogsReturnsUnwrapped — when the
// container is still Running AND the kubelet has no logs to offer, there's
// genuinely nothing for the user beyond the raw attach error.
func TestDiagnoseAttachFailure_RunningPodWithoutLogsReturnsUnwrapped(t *testing.T) {
	shortDiagnoseTiming(t, 50*time.Millisecond, 10*time.Millisecond)
	stubDumpPodLogs(t, emptyLogs)

	pod := runningSpawnPod("ns", "spawn")
	clientset := fake.NewSimpleClientset(pod)
	orig := errors.New("transient attach error")

	err := diagnoseAttachFailure(context.Background(), clientset, "ns", "spawn", orig)

	var afe *AttachFailedError
	if errors.As(err, &afe) {
		t.Fatalf("non-terminal pod with no logs must not be wrapped, got: %v", err)
	}
	if !errors.Is(err, orig) {
		t.Errorf("original error must remain reachable, got: %v", err)
	}
}

func TestDiagnoseAttachFailure_NilErrorReturnsNil(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	if got := diagnoseAttachFailure(context.Background(), clientset, "ns", "spawn", nil); got != nil {
		t.Errorf("nil orig error must produce nil result, got %v", got)
	}
}

// TestDiagnoseAttachFailure_MissingPodReturnsUnwrapped — when the apiserver
// definitively reports the pod as gone (NotFound), surface a clearer message
// than the bare kubelet error.
func TestDiagnoseAttachFailure_MissingPodReturnsUnwrapped(t *testing.T) {
	shortDiagnoseTiming(t, 50*time.Millisecond, 10*time.Millisecond)
	stubDumpPodLogs(t, emptyLogs)

	clientset := fake.NewSimpleClientset()
	orig := errors.New("attach failed")

	start := time.Now()
	err := diagnoseAttachFailure(context.Background(), clientset, "ns", "spawn", orig)
	elapsed := time.Since(start)

	var afe *AttachFailedError
	if errors.As(err, &afe) {
		t.Fatalf("missing pod must not be wrapped as AttachFailedError, got: %v", err)
	}
	if !errors.Is(err, orig) {
		t.Errorf("original error must remain reachable, got: %v", err)
	}
	if !strings.Contains(err.Error(), "no longer exists") {
		t.Errorf("expected NotFound wrapper to clarify pod is gone, got: %v", err)
	}
	if elapsed > 20*time.Millisecond {
		t.Errorf("NotFound must short-circuit immediately, took %v", elapsed)
	}
}

// TestDiagnoseAttachFailure_LogsArriveBeforeTerminalState — Gap 1: defense
// in depth so the kubelet log endpoint flushing stderr before the status
// manager publishes terminal state still surfaces the cause to the user.
func TestDiagnoseAttachFailure_LogsArriveBeforeTerminalState(t *testing.T) {
	shortDiagnoseTiming(t, 100*time.Millisecond, 10*time.Millisecond)
	const podStderr = "Error: kernel Lockdown LSM is in 'confidentiality' mode"
	var fetches atomic.Int32
	stubDumpPodLogs(t, func(_ context.Context, _ kubernetes.Interface, _, _ string) string {
		if fetches.Add(1) >= 2 {
			return podStderr
		}
		return ""
	})

	clientset := fake.NewSimpleClientset(runningSpawnPod("ns", "spawn"))
	orig := errors.New("Internal error occurred: error attaching to container: container is in CONTAINER_EXITED state")

	err := diagnoseAttachFailure(context.Background(), clientset, "ns", "spawn", orig)

	var afe *AttachFailedError
	if !errors.As(err, &afe) {
		t.Fatalf("expected *AttachFailedError once logs arrive mid-poll, got %T: %v", err, err)
	}
	if !strings.Contains(afe.LastLogs, "Lockdown LSM") {
		t.Errorf("LastLogs did not capture pod stderr from late iteration: %q", afe.LastLogs)
	}
	if afe.ExitCode != nil {
		t.Errorf("ExitCode must be nil when only logs (not terminal state) were observed, got %v", *afe.ExitCode)
	}
}

// TestDiagnoseAttachFailure_TerminalAfterRaceIsWrapped pins the kubelet
// status-update race: the streaming endpoint reports CONTAINER_EXITED before
// the status manager publishes the terminal state.
func TestDiagnoseAttachFailure_TerminalAfterRaceIsWrapped(t *testing.T) {
	shortDiagnoseTiming(t, 200*time.Millisecond, 10*time.Millisecond)

	clientset := fake.NewSimpleClientset(runningSpawnPod("ns", "spawn"))
	var calls atomic.Int32
	terminal := terminatedSpawnPod("ns", "spawn", 1, "Error",
		"kernel Lockdown LSM is in 'confidentiality' mode")
	clientset.PrependReactor("get", "pods", func(_ k8stesting.Action) (bool, runtime.Object, error) {
		if calls.Add(1) >= 3 {
			return true, terminal, nil
		}
		return true, runningSpawnPod("ns", "spawn"), nil
	})

	orig := errors.New("Internal error occurred: error attaching to container: container is in CONTAINER_EXITED state")
	err := diagnoseAttachFailure(context.Background(), clientset, "ns", "spawn", orig)

	var afe *AttachFailedError
	if !errors.As(err, &afe) {
		t.Fatalf("expected *AttachFailedError once status lands, got %T: %v", err, err)
	}
	if afe.ExitCode == nil || *afe.ExitCode != 1 {
		t.Errorf("ExitCode: got %v, want 1", afe.ExitCode)
	}
	if !strings.Contains(afe.Message, "Lockdown LSM") {
		t.Errorf("Message did not propagate termination message: %q", afe.Message)
	}
	if !errors.Is(err, orig) {
		t.Errorf("Unwrap should expose the original attach error")
	}
}

// TestDiagnoseAttachFailure_NeverTerminalNoLogsReturnsUnwrapped — when the
// kubelet never publishes a terminal state AND has no logs (the kubelet is
// truly unreachable), we surface origErr instead of hanging.
func TestDiagnoseAttachFailure_NeverTerminalNoLogsReturnsUnwrapped(t *testing.T) {
	shortDiagnoseTiming(t, 50*time.Millisecond, 10*time.Millisecond)
	stubDumpPodLogs(t, emptyLogs)

	clientset := fake.NewSimpleClientset(runningSpawnPod("ns", "spawn"))
	orig := errors.New("Internal error occurred: error attaching to container: container is in CONTAINER_EXITED state")

	start := time.Now()
	err := diagnoseAttachFailure(context.Background(), clientset, "ns", "spawn", orig)
	elapsed := time.Since(start)

	var afe *AttachFailedError
	if errors.As(err, &afe) {
		t.Fatalf("non-terminal pod with no logs must not be wrapped, got: %v", err)
	}
	if !errors.Is(err, orig) {
		t.Errorf("original error must remain reachable, got: %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("diagnose blew past the configured 50ms timeout: %v", elapsed)
	}
}

// TestDiagnoseAttachFailure_NoTerminalButLogsAreSurfaced — defense in depth:
// even if the kubelet status manager doesn't publish the terminal state
// within our budget, the kubelet's log endpoint usually already has stderr.
func TestDiagnoseAttachFailure_NoTerminalButLogsAreSurfaced(t *testing.T) {
	shortDiagnoseTiming(t, 50*time.Millisecond, 10*time.Millisecond)
	const podStderr = "Error: kernel Lockdown LSM is in 'confidentiality' mode; BPF cannot read kernel RAM"
	stubDumpPodLogs(t, stubLogs(podStderr))

	clientset := fake.NewSimpleClientset(runningSpawnPod("ns", "spawn"))
	orig := errors.New("Internal error occurred: error attaching to container: container is in CONTAINER_EXITED state")

	err := diagnoseAttachFailure(context.Background(), clientset, "ns", "spawn", orig)

	var afe *AttachFailedError
	if !errors.As(err, &afe) {
		t.Fatalf("expected *AttachFailedError so the user sees pod logs, got %T: %v", err, err)
	}
	if afe.ExitCode != nil {
		t.Errorf("ExitCode must be nil when terminal state was not observed, got %v", *afe.ExitCode)
	}
	if !strings.Contains(afe.LastLogs, "Lockdown LSM") {
		t.Errorf("LastLogs did not propagate pod stderr: %q", afe.LastLogs)
	}
	if !errors.Is(err, orig) {
		t.Errorf("Unwrap must still expose the original attach error")
	}
	msg := afe.Error()
	for _, want := range []string{
		"attach to ns/spawn failed",
		"Lockdown LSM",
		"kubectl -n ns logs spawn",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("formatted error missing %q\n got: %s", want, msg)
		}
	}
}

// TestDiagnoseAttachFailure_PollAbortsOnContextCancel pins the cancellation
// path inside the poll loop: if the caller cancels ctx mid-poll, we must
// surface origErr immediately, not hang.
func TestDiagnoseAttachFailure_PollAbortsOnContextCancel(t *testing.T) {
	shortDiagnoseTiming(t, 5*time.Second, 50*time.Millisecond)

	clientset := fake.NewSimpleClientset(runningSpawnPod("ns", "spawn"))
	orig := errors.New("attach failed")

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := diagnoseAttachFailure(ctx, clientset, "ns", "spawn", orig)
	elapsed := time.Since(start)

	var afe *AttachFailedError
	if errors.As(err, &afe) {
		t.Fatalf("cancelled poll must surface origErr, got: %v", err)
	}
	if !errors.Is(err, orig) {
		t.Errorf("original error must remain reachable, got: %v", err)
	}
	if elapsed > time.Second {
		t.Errorf("poll did not abort promptly on cancel: %v", elapsed)
	}
}

// TestDiagnoseAttachFailure_UserCancelledOrigErrShortCircuits — when the
// user hits Ctrl-C (or timeout/SIGTERM), the SPDY stream returns an error
// that wraps context.Canceled.
func TestDiagnoseAttachFailure_UserCancelledOrigErrShortCircuits(t *testing.T) {
	clientset := fake.NewSimpleClientset(runningSpawnPod("ns", "spawn"))
	wrapped := fmt.Errorf("stream interrupted: %w", context.Canceled)

	err := diagnoseAttachFailure(context.Background(), clientset, "ns", "spawn", wrapped)

	var afe *AttachFailedError
	if errors.As(err, &afe) {
		t.Fatalf("user-cancelled attach must not produce diagnostic dump, got: %v", err)
	}
	if !errors.Is(err, wrapped) {
		t.Errorf("wrapped error must remain reachable, got: %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("context.Canceled must be unwrappable, got: %v", err)
	}
}

func TestDiagnoseAttachFailure_CancelledContextReturnsUnwrapped(t *testing.T) {
	pod := terminatedSpawnPod("ns", "spawn", 1, "Error", "anything")
	clientset := fake.NewSimpleClientset(pod)
	orig := errors.New("attach failed")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := diagnoseAttachFailure(ctx, clientset, "ns", "spawn", orig)

	var afe *AttachFailedError
	if errors.As(err, &afe) {
		t.Fatalf("cancelled context must not be wrapped in AttachFailedError, got: %v", err)
	}
	if !errors.Is(err, orig) {
		t.Errorf("original error must remain reachable, got: %v", err)
	}
}

func TestAttachFailedError_FormatWithoutExitCode(t *testing.T) {
	afe := &AttachFailedError{
		Namespace: "ns",
		PodName:   "spawn",
		Cause:     errors.New("transport hung up"),
	}
	want := "attach to ns/spawn: transport hung up"
	if got := afe.Error(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestPrimaryContainerStatus_PrefersNamedContainer(t *testing.T) {
	pod := &corev1.Pod{
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "sidecar"},
				{Name: "podtrace", Image: "ghcr.io/gma1k/podtrace:0.12.1"},
			},
		},
	}
	cs := primaryContainerStatus(pod)
	if cs == nil || cs.Name != "podtrace" {
		t.Fatalf("expected podtrace container, got %v", cs)
	}
}

func TestPrimaryContainerStatus_FallsBackToFirstWhenNamedAbsent(t *testing.T) {
	pod := &corev1.Pod{
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{{Name: "other"}},
		},
	}
	cs := primaryContainerStatus(pod)
	if cs == nil || cs.Name != "other" {
		t.Fatalf("expected fallback to first container, got %v", cs)
	}
}

func TestPrimaryContainerStatus_EmptyReturnsNil(t *testing.T) {
	if primaryContainerStatus(&corev1.Pod{}) != nil {
		t.Errorf("expected nil for empty status list")
	}
	if primaryContainerStatus(nil) != nil {
		t.Errorf("expected nil for nil pod")
	}
}

func terminatedSpawnPod(namespace, name string, exitCode int32, reason, message string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status: corev1.PodStatus{
			Phase: corev1.PodFailed,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "podtrace",
				State: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{
						ExitCode: exitCode,
						Reason:   reason,
						Message:  message,
					},
				},
			}},
		},
	}
}

func runningSpawnPod(namespace, name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:  "podtrace",
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}},
		},
	}
}
