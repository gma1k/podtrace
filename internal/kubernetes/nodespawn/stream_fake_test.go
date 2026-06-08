package nodespawn

import (
	"bytes"
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

// --- unschedulableReason (pure) ---

func TestUnschedulableReason(t *testing.T) {
	unschedulable := &corev1.Pod{
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{{
				Type:    corev1.PodScheduled,
				Status:  corev1.ConditionFalse,
				Reason:  corev1.PodReasonUnschedulable,
				Message: "0/3 nodes are available: 3 Insufficient cpu.",
			}},
		},
	}
	if got, want := unschedulableReason(unschedulable), "0/3 nodes are available: 3 Insufficient cpu."; got != want {
		t.Errorf("unschedulableReason = %q, want %q", got, want)
	}

	scheduled := &corev1.Pod{
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{{
				Type:   corev1.PodScheduled,
				Status: corev1.ConditionTrue,
			}},
		},
	}
	if got := unschedulableReason(scheduled); got != "" {
		t.Errorf("scheduled pod should report no reason, got %q", got)
	}

	if got := unschedulableReason(&corev1.Pod{}); got != "" {
		t.Errorf("pod with no conditions should report no reason, got %q", got)
	}
}

// --- imagePullFailureReason (pure) ---

func TestImagePullFailureReason(t *testing.T) {
	cases := []struct {
		reason  string
		message string
		want    string
	}{
		{"ImagePullBackOff", "Back-off pulling image", "ImagePullBackOff: Back-off pulling image"},
		{"ErrImagePull", "rpc error: not found", "ErrImagePull: rpc error: not found"},
		{"InvalidImageName", "couldn't parse image", "InvalidImageName: couldn't parse image"},
	}
	for _, tc := range cases {
		t.Run(tc.reason, func(t *testing.T) {
			p := pendingPodWithContainerWaiting("ns", "spawn", tc.reason, tc.message)
			if got := imagePullFailureReason(p); got != tc.want {
				t.Errorf("imagePullFailureReason = %q, want %q", got, tc.want)
			}
		})
	}

	p := pendingPodWithContainerWaiting("ns", "spawn", "ContainerCreating", "still pulling")
	if got := imagePullFailureReason(p); got != "" {
		t.Errorf("ContainerCreating should not be an image-pull failure, got %q", got)
	}

	if got := imagePullFailureReason(&corev1.Pod{}); got != "" {
		t.Errorf("pod with no container statuses should report no reason, got %q", got)
	}
}

// --- waitForPodRunningOrTerminated (fake clientset) ---

// --- WaitForExitCode (fake clientset) ---

func TestWaitForExitCode_TerminatedReturnsExitCode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "spawn"},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "podtrace",
				State: corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{ExitCode: 42},
				},
			}},
		},
	}
	cs := fake.NewSimpleClientset(pod)
	if got := WaitForExitCode(ctx, cs, "ns", "spawn"); got != 42 {
		t.Errorf("WaitForExitCode = %d, want 42", got)
	}
}

func TestWaitForExitCode_ContextCancelledReturnsMinusOne(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

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
	if got := WaitForExitCode(ctx, cs, "ns", "spawn"); got != -1 {
		t.Errorf("WaitForExitCode (cancelled) = %d, want -1", got)
	}
}

func TestWaitForExitCode_NotFoundReturnsMinusOne(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cs := fake.NewSimpleClientset() // no such pod
	if got := WaitForExitCode(ctx, cs, "ns", "missing"); got != -1 {
		t.Errorf("WaitForExitCode (not found) = %d, want -1", got)
	}
}

// --- streamLogs (fake clientset) ---

func TestStreamLogs_CopiesFakeLogStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "spawn"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "podtrace"}},
		},
	}
	cs := fake.NewSimpleClientset(pod)

	var out bytes.Buffer
	if err := streamLogs(ctx, cs, pod, &out); err != nil {
		t.Fatalf("streamLogs error: %v", err)
	}
	// The fake clientset returns the canned body "fake logs".
	if got := out.String(); got != "fake logs" {
		t.Errorf("streamLogs copied %q, want %q", got, "fake logs")
	}
}

// --- AttachToPod (fake clientset) ---

func TestAttachToPod_NilPod(t *testing.T) {
	cs := fake.NewSimpleClientset()
	_, err := AttachToPod(context.Background(), &rest.Config{}, cs, nil, genericiooptions.IOStreams{})
	if err == nil {
		t.Fatalf("expected error for nil pod")
	}
}
