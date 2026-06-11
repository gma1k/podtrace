package nodespawn

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// TestWaitForExitCode_RetriesTransientErrors: a single transient Get error
// used to report exit -1, which the caller treats as failure and tears the
// spawn pod down.
func TestWaitForExitCode_RetriesTransientErrors(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "spawn", Namespace: "ns1"},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
			{Name: "main", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 3}}},
		}},
	}
	clientset := fake.NewSimpleClientset(pod)
	var mu sync.Mutex
	failures := 2
	clientset.PrependReactor("get", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		mu.Lock()
		defer mu.Unlock()
		if failures > 0 {
			failures--
			return true, nil, errors.New("transient apiserver hiccup")
		}
		return false, nil, nil
	})

	if exit := WaitForExitCode(context.Background(), clientset, "ns1", "spawn"); exit != 3 {
		t.Errorf("exit = %d, want 3 (transient errors must be retried)", exit)
	}
}

// TestWaitForExitCode_OutlastsLongTraces: the old 30s wall-clock cap
// reported -1 for any container still running past it, tearing down
// healthy long traces in the log-follow fallback. The wait must keep
// polling until the container actually terminates.
func TestWaitForExitCode_OutlastsLongTraces(t *testing.T) {
	running := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "spawn", Namespace: "ns1"},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
			{Name: "main", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}},
		}},
	}
	clientset := fake.NewSimpleClientset(running)
	var mu sync.Mutex
	polls := 0
	clientset.PrependReactor("get", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		mu.Lock()
		defer mu.Unlock()
		polls++
		if polls < 4 {
			return false, nil, nil // still running
		}
		done := running.DeepCopy()
		done.Status.ContainerStatuses[0].State = corev1.ContainerState{
			Terminated: &corev1.ContainerStateTerminated{ExitCode: 0},
		}
		return true, done, nil
	})

	if exit := WaitForExitCode(context.Background(), clientset, "ns1", "spawn"); exit != 0 {
		t.Errorf("exit = %d, want 0 once the container terminates", exit)
	}
}

func TestWaitForExitCode_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	clientset := fake.NewSimpleClientset()
	if exit := WaitForExitCode(ctx, clientset, "ns1", "gone"); exit != -1 {
		t.Errorf("exit = %d, want -1 on cancelled context", exit)
	}
}

// reapPodFull builds a spawn pod with the labels the reaper inspects.
func reapPodFull(name string, pid int, bootID string, age time.Duration, deadline *int64) *corev1.Pod {
	labels := map[string]string{
		LabelManagedBy: ManagedByValue,
		LabelOwnerPID:  fmt.Sprintf("%d", pid),
		LabelCreatedAt: fmt.Sprintf("%d", time.Now().Add(-age).Unix()),
	}
	if bootID != "" {
		labels[LabelOwnerBootID] = bootID
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns1", Labels: labels},
		Spec:       corev1.PodSpec{ActiveDeadlineSeconds: deadline},
	}
}

// TestReaper_ForeignBootIDNotReaped: kill(pid, 0) only means something on
// the machine that spawned the pod. Two hosts whose names collide after
// label sanitization used to reap each other's LIVE spawn pods.
func TestReaper_ForeignBootIDNotReaped(t *testing.T) {
	savedBootID := MachineBootID
	MachineBootID = func() string { return "local-boot-id" }
	defer func() { MachineBootID = savedBootID }()

	foreign := reapPodFull("foreign", 4242, "other-boot-id", 10*time.Minute, nil)
	local := reapPodFull("local", 4242, "local-boot-id", 10*time.Minute, nil)
	clientset := fake.NewSimpleClientset(foreign, local)

	reaped, err := reapStaleWithLiveness(context.Background(), clientset, "ns1", "", func(int) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	if reaped != 1 {
		t.Fatalf("reaped %d pods, want exactly the local one", reaped)
	}
	if _, err := clientset.CoreV1().Pods("ns1").Get(context.Background(), "foreign", metav1.GetOptions{}); err != nil {
		t.Error("foreign machine's pod must not be reaped on a local liveness verdict")
	}
	if _, err := clientset.CoreV1().Pods("ns1").Get(context.Background(), "local", metav1.GetOptions{}); err == nil {
		t.Error("local orphan must be reaped")
	}
}

// TestReaper_ExpiredPodReapedRegardlessOfOwner: pods older than the hard
// age bound are orphans no matter which machine owns them — ReaperMaxAge
// was defined but never enforced.
func TestReaper_ExpiredPodReapedRegardlessOfOwner(t *testing.T) {
	savedBootID := MachineBootID
	MachineBootID = func() string { return "local-boot-id" }
	defer func() { MachineBootID = savedBootID }()

	expired := reapPodFull("expired", 4242, "other-boot-id", ReaperMaxAge+time.Hour, nil)
	clientset := fake.NewSimpleClientset(expired)

	reaped, err := reapStaleWithLiveness(context.Background(), clientset, "ns1", "", func(int) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if reaped != 1 {
		t.Errorf("reaped %d, want 1 (expired pod)", reaped)
	}
}

// TestReaper_LongDeadlineExtendsAgeBound: a trace spawned with an explicit
// deadline beyond ReaperMaxAge is not an orphan until that deadline (plus
// grace) passes.
func TestReaper_LongDeadlineExtendsAgeBound(t *testing.T) {
	savedBootID := MachineBootID
	MachineBootID = func() string { return "local-boot-id" }
	defer func() { MachineBootID = savedBootID }()

	deadline := int64((4 * time.Hour).Seconds())
	longTrace := reapPodFull("long-trace", 4242, "other-boot-id", 3*time.Hour, &deadline)
	clientset := fake.NewSimpleClientset(longTrace)

	reaped, err := reapStaleWithLiveness(context.Background(), clientset, "ns1", "", func(int) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if reaped != 0 {
		t.Errorf("reaped %d, want 0: 3h-old pod with a 4h deadline is not an orphan", reaped)
	}
}
