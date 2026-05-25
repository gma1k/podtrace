package nodespawn

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

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

func TestDiagnoseAttachFailure_RunningPodReturnsUnwrapped(t *testing.T) {
	pod := runningSpawnPod("ns", "spawn")
	clientset := fake.NewSimpleClientset(pod)
	orig := errors.New("transient attach error")

	err := diagnoseAttachFailure(context.Background(), clientset, "ns", "spawn", orig)

	var afe *AttachFailedError
	if errors.As(err, &afe) {
		t.Fatalf("running pod must not be wrapped in AttachFailedError, got: %v", err)
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

func TestDiagnoseAttachFailure_MissingPodReturnsUnwrapped(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	orig := errors.New("attach failed")

	err := diagnoseAttachFailure(context.Background(), clientset, "ns", "spawn", orig)

	var afe *AttachFailedError
	if errors.As(err, &afe) {
		t.Fatalf("missing pod must not be wrapped in AttachFailedError, got: %v", err)
	}
	if !errors.Is(err, orig) {
		t.Errorf("original error must remain reachable, got: %v", err)
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
