package nodespawn

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

func pendingPodWithContainerWaiting(namespace, name, reason, message string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Status: corev1.PodStatus{
			Phase: corev1.PodPending,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "podtrace",
				State: corev1.ContainerState{
					Waiting: &corev1.ContainerStateWaiting{
						Reason:  reason,
						Message: message,
					},
				},
			}},
		},
	}
}

func TestContainerStartFailureReason_DetectsFatalWaitingReasons(t *testing.T) {
	cases := []struct {
		reason  string
		message string
		want    string
	}{
		{"CreateContainerError", "no such file or directory", "CreateContainerError: no such file or directory"},
		{"CreateContainerConfigError", "invalid env", "CreateContainerConfigError: invalid env"},
		{"RunContainerError", "OCI runtime create failed", "RunContainerError: OCI runtime create failed"},
		{"PostStartHookError", "hook handler failed", "PostStartHookError: hook handler failed"},
	}
	for _, tc := range cases {
		t.Run(tc.reason, func(t *testing.T) {
			p := pendingPodWithContainerWaiting("ns", "spawn", tc.reason, tc.message)
			if got := containerStartFailureReason(p); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestContainerStartFailureReason_SilentOnTransientWaiting(t *testing.T) {
	cases := []string{"ContainerCreating", "PodInitializing", "", "Pending"}
	for _, reason := range cases {
		t.Run(reason, func(t *testing.T) {
			p := pendingPodWithContainerWaiting("ns", "spawn", reason, "still working on it")
			if got := containerStartFailureReason(p); got != "" {
				t.Errorf("transient %q should not be reported as fatal, got %q", reason, got)
			}
		})
	}
}

func TestStuckPodEventReason_SurfacesFailedMount(t *testing.T) {
	prev := stuckPodEventReason
	stuckPodEventReason = func(_ context.Context, _ kubernetes.Interface, p *corev1.Pod) string {
		ev := corev1.Event{
			Reason:        "FailedMount",
			Message:       "MountVolume.SetUp failed for volume \"securityfs\" : hostPath type check failed: /host/sys/kernel/security is not a directory",
			LastTimestamp: metav1.NewTime(time.Now()),
		}
		return ev.Reason + ": " + strings.TrimSpace(ev.Message)
	}
	t.Cleanup(func() { stuckPodEventReason = prev })

	got := stuckPodEventReason(context.Background(), fake.NewSimpleClientset(), &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "spawn"},
	})
	for _, want := range []string{"FailedMount", "securityfs", "hostPath type check failed"} {
		if !strings.Contains(got, want) {
			t.Errorf("formatted event missing %q\n got: %s", want, got)
		}
	}
}

func TestStuckPodEventReason_NoFatalEventsReturnsEmpty(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&corev1.Event{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "evt-1"},
			InvolvedObject: corev1.ObjectReference{
				Kind: "Pod", Namespace: "ns", Name: "spawn",
			},
			Reason:        "Scheduled",
			Message:       "Successfully assigned ns/spawn to node1",
			LastTimestamp: metav1.NewTime(time.Now()),
		},
		&corev1.Event{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "evt-2"},
			InvolvedObject: corev1.ObjectReference{
				Kind: "Pod", Namespace: "ns", Name: "spawn",
			},
			Reason:        "Pulling",
			Message:       "Pulling image \"ghcr.io/gma1k/podtrace:dev\"",
			LastTimestamp: metav1.NewTime(time.Now()),
		},
	)
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "spawn"}}
	if got := stuckPodEventReason(context.Background(), clientset, p); got != "" {
		t.Errorf("benign events must not fire fatal-reason path, got: %s", got)
	}
}