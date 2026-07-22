package nodespawn

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestStuckPodEventReason_ReturnsNewestFatalReason(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "spawn"}}
	older := metav1.NewTime(time.Now().Add(-time.Minute))
	newer := metav1.NewTime(time.Now())
	cs := fake.NewSimpleClientset(
		&corev1.Event{
			ObjectMeta:     metav1.ObjectMeta{Namespace: "ns", Name: "old"},
			InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "spawn", Namespace: "ns"},
			Reason:         "FailedAttachVolume",
			Message:        "attach timed out",
			LastTimestamp:  older,
		},
		&corev1.Event{
			ObjectMeta:     metav1.ObjectMeta{Namespace: "ns", Name: "new"},
			InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "spawn", Namespace: "ns"},
			Reason:         "FailedMount",
			Message:        "  securityfs hostPath check failed  ",
			LastTimestamp:  newer,
		},
	)

	got := stuckPodEventReason(context.Background(), cs, pod)
	if got != "FailedMount: securityfs hostPath check failed" {
		t.Errorf("stuckPodEventReason = %q, want the trimmed newest fatal reason", got)
	}
}

func TestWaitForExitCode_ContextCancelledDuringPoll(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "spawn"},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:  "podtrace",
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}},
		},
	}
	cs := fake.NewSimpleClientset(pod)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if got := WaitForExitCode(ctx, cs, "ns", "spawn"); got != -1 {
		t.Errorf("WaitForExitCode = %d, want -1 when ctx cancels while the container keeps running", got)
	}
}
