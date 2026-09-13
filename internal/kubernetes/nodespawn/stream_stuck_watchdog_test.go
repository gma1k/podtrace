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

func TestAWedgedPodIsDiagnosedEvenWhenItStopsChanging(t *testing.T) {
	prevThreshold := stuckPodEventThreshold
	stuckPodEventThreshold = 50 * time.Millisecond
	t.Cleanup(func() { stuckPodEventThreshold = prevThreshold })

	prev := stuckPodEventReason
	stuckPodEventReason = func(_ context.Context, _ kubernetes.Interface, _ *corev1.Pod) string {
		return "FailedMount: configmap references non-existent config key: vmlinux.btf"
	}
	t.Cleanup(func() { stuckPodEventReason = prev })

	pending := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "spawn"},
		Status:     corev1.PodStatus{Phase: corev1.PodPending},
	}
	cs := fake.NewSimpleClientset(pending)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := waitForPodRunningOrTerminated(ctx, cs, "ns", "spawn")
	if err == nil {
		t.Fatal("wait succeeded on a pod that never left Pending")
	}
	if !strings.Contains(err.Error(), "FailedMount") {
		t.Errorf("error = %q, want the mount failure.\n\nA pod wedged in ContainerCreating "+
			"stops changing: the kubelet keeps emitting Events but the Pod object does not "+
			"update, so a check that only runs inside the watch callback never fires again. "+
			"The operator then waits out the whole budget for \"timed out waiting for the "+
			"condition\", which names neither the volume nor the path.", err)
	}
}

func TestAWatchdogStopIsSafeToCallTwice(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := newStuckPodWatchdog(ctx, fake.NewSimpleClientset(), "ns", "spawn", cancel)
	w.stop()
	w.stop()

	if got := w.reason(); got != "" {
		t.Errorf("reason = %q, want empty when nothing was diagnosed", got)
	}
}

func TestTheWatchdogStopsWhenItsContextEnds(t *testing.T) {
	prevThreshold := stuckPodEventThreshold
	stuckPodEventThreshold = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	w := newStuckPodWatchdog(ctx, fake.NewSimpleClientset(), "ns", "gone", cancel)
	cancel()

	// stop joins the goroutine, so restoring the package variable afterwards
	// cannot race the poll that read it.
	w.stop()
	stuckPodEventThreshold = prevThreshold

	if got := w.reason(); got != "" {
		t.Errorf("reason = %q after the context ended, want empty", got)
	}
}

func TestTheWatchdogIgnoresAPodThatIsNotPending(t *testing.T) {
	prevThreshold := stuckPodEventThreshold
	stuckPodEventThreshold = 10 * time.Millisecond
	t.Cleanup(func() { stuckPodEventThreshold = prevThreshold })

	prev := stuckPodEventReason
	stuckPodEventReason = func(_ context.Context, _ kubernetes.Interface, _ *corev1.Pod) string {
		t.Error("a Running pod was consulted for a stuck reason")
		return "should not happen"
	}
	defer func() { stuckPodEventReason = prev }()

	running := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "spawn"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := newStuckPodWatchdog(ctx, fake.NewSimpleClientset(running), "ns", "spawn", cancel)
	time.Sleep(60 * time.Millisecond)
	w.stop()

	if got := w.reason(); got != "" {
		t.Errorf("reason = %q for a Running pod", got)
	}
}

func TestAStoppedWatchdogLeavesNoGoroutineBehind(t *testing.T) {
	prevThreshold := stuckPodEventThreshold
	stuckPodEventThreshold = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := newStuckPodWatchdog(ctx, fake.NewSimpleClientset(), "ns", "spawn", cancel)
	w.stop()
	stuckPodEventThreshold = prevThreshold

	select {
	case <-w.finished:
	default:
		t.Error("stop returned while the poll goroutine was still running.\n\nstop is the " +
			"only join point: a watchdog that outlives its wait keeps polling the apiserver " +
			"for a pod nobody is waiting on.")
	}
}
