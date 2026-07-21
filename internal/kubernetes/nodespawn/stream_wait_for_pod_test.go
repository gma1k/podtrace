package nodespawn

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientfeatures "k8s.io/client-go/features"
	clientfeaturestesting "k8s.io/client-go/features/testing"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

func useClassicListWatch(t *testing.T) {
	t.Helper()
	clientfeaturestesting.SetFeatureDuringTest(t, clientfeatures.WatchListClient, false)
}

func TestWaitForPodRunning_RunningResolvesImmediately(t *testing.T) {
	useClassicListWatch(t)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "spawn"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	cs := fake.NewSimpleClientset(pod)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got, err := waitForPodRunningOrTerminated(ctx, cs, "ns", "spawn")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.Status.Phase != corev1.PodRunning {
		t.Fatalf("expected Running pod, got %+v", got)
	}
}

func TestWaitForPodRunning_TerminalPhasesResolve(t *testing.T) {
	for _, phase := range []corev1.PodPhase{corev1.PodSucceeded, corev1.PodFailed} {
		t.Run(string(phase), func(t *testing.T) {
			useClassicListWatch(t)
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "spawn"},
				Status:     corev1.PodStatus{Phase: phase},
			}
			cs := fake.NewSimpleClientset(pod)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			got, err := waitForPodRunningOrTerminated(ctx, cs, "ns", "spawn")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == nil || got.Status.Phase != phase {
				t.Fatalf("expected phase %s, got %+v", phase, got)
			}
		})
	}
}

func TestWaitForPodRunning_UnschedulableIsFatal(t *testing.T) {
	useClassicListWatch(t)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "spawn"},
		Status: corev1.PodStatus{
			Phase: corev1.PodPending,
			Conditions: []corev1.PodCondition{{
				Type:    corev1.PodScheduled,
				Status:  corev1.ConditionFalse,
				Reason:  corev1.PodReasonUnschedulable,
				Message: "0/3 nodes are available: 3 node(s) had untolerated taint",
			}},
		},
	}
	cs := fake.NewSimpleClientset(pod)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := waitForPodRunningOrTerminated(ctx, cs, "ns", "spawn")
	if err == nil || !strings.Contains(err.Error(), "cannot be scheduled") {
		t.Fatalf("expected unschedulable error, got %v", err)
	}
}

func TestWaitForPodRunning_ImagePullFailureIsFatal(t *testing.T) {
	useClassicListWatch(t)
	pod := pendingPodWithContainerWaiting("ns", "spawn", "ImagePullBackOff", "Back-off pulling image")
	cs := fake.NewSimpleClientset(pod)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := waitForPodRunningOrTerminated(ctx, cs, "ns", "spawn")
	if err == nil || !strings.Contains(err.Error(), "image pull failed") {
		t.Fatalf("expected image pull error, got %v", err)
	}
}

func TestWaitForPodRunning_ContainerStartFailureIsFatal(t *testing.T) {
	useClassicListWatch(t)
	pod := pendingPodWithContainerWaiting("ns", "spawn", "CreateContainerConfigError", "secret not found")
	cs := fake.NewSimpleClientset(pod)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := waitForPodRunningOrTerminated(ctx, cs, "ns", "spawn")
	if err == nil || !strings.Contains(err.Error(), "container failed to start") {
		t.Fatalf("expected container-start error, got %v", err)
	}
}

func TestWaitForPodRunning_DeletedBeforeRunning(t *testing.T) {
	useClassicListWatch(t)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "spawn"},
		Status:     corev1.PodStatus{Phase: corev1.PodPending},
	}
	cs := fake.NewSimpleClientset(pod)

	go func() {
		time.Sleep(150 * time.Millisecond)
		_ = cs.CoreV1().Pods("ns").Delete(context.Background(), "spawn", metav1.DeleteOptions{})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := waitForPodRunningOrTerminated(ctx, cs, "ns", "spawn")
	if err == nil || !strings.Contains(err.Error(), "deleted before reaching Running") {
		t.Fatalf("expected deleted-before-running error, got %v", err)
	}
}

func TestWaitForPodRunning_PendingThenRunning(t *testing.T) {
	useClassicListWatch(t)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "spawn"},
		Status:     corev1.PodStatus{Phase: corev1.PodPending},
	}
	cs := fake.NewSimpleClientset(pod)

	go func() {
		time.Sleep(100 * time.Millisecond)
		p, err := cs.CoreV1().Pods("ns").Get(context.Background(), "spawn", metav1.GetOptions{})
		if err != nil {
			return
		}
		p = p.DeepCopy()
		p.Status.Phase = corev1.PodRunning
		_, _ = cs.CoreV1().Pods("ns").Update(context.Background(), p, metav1.UpdateOptions{})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got, err := waitForPodRunningOrTerminated(ctx, cs, "ns", "spawn")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.Status.Phase != corev1.PodRunning {
		t.Fatalf("expected Running after transition, got %+v", got)
	}
}

func TestStreamLogs_PropagatesCopyError(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "spawn"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "podtrace"}}},
	}
	cs := fake.NewSimpleClientset(pod)

	if err := streamLogs(context.Background(), cs, pod, failingWriter{}); err == nil {
		t.Fatalf("expected the destination write error to propagate")
	}
}

func TestWaitForPodRunning_StuckPendingConsultsEvents(t *testing.T) {
	useClassicListWatch(t)

	prevThreshold := stuckPodEventThreshold
	stuckPodEventThreshold = time.Millisecond
	t.Cleanup(func() { stuckPodEventThreshold = prevThreshold })

	prevReason := stuckPodEventReason
	stuckPodEventReason = func(context.Context, kubernetes.Interface, *corev1.Pod) string {
		return "FailedMount: securityfs hostPath check failed"
	}
	t.Cleanup(func() { stuckPodEventReason = prevReason })

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "spawn"},
		Status:     corev1.PodStatus{Phase: corev1.PodPending},
	}
	cs := fake.NewSimpleClientset(pod)

	go func() {
		time.Sleep(40 * time.Millisecond)
		p, err := cs.CoreV1().Pods("ns").Get(context.Background(), "spawn", metav1.GetOptions{})
		if err != nil {
			return
		}
		p = p.DeepCopy()
		if p.Annotations == nil {
			p.Annotations = map[string]string{}
		}
		p.Annotations["touch"] = "1"
		_, _ = cs.CoreV1().Pods("ns").Update(context.Background(), p, metav1.UpdateOptions{})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := waitForPodRunningOrTerminated(ctx, cs, "ns", "spawn")
	if err == nil || !strings.Contains(err.Error(), "stuck in Pending") {
		t.Fatalf("expected stuck-in-Pending error, got %v", err)
	}
}
