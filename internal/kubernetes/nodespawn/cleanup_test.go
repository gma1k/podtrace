package nodespawn

import (
	"context"
	"os"
	"strconv"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func reapPod(name, host string, pid int) *corev1.Pod {
	labels := map[string]string{
		LabelManagedBy: ManagedByValue,
	}
	if host != "" {
		labels[LabelOwnerHost] = host
	}
	if pid >= 0 {
		labels[LabelOwnerPID] = strconv.Itoa(pid)
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "ns1",
			Labels:    labels,
		},
	}
}

// reapPodWithBadPID is the malformed-label case ("abc" instead of an int).
func reapPodWithBadPID(name, host string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "ns1",
			Labels: map[string]string{
				LabelManagedBy: ManagedByValue,
				LabelOwnerHost: host,
				LabelOwnerPID:  "abc",
			},
		},
	}
}

func TestDeletePod_SwallowsNotFound(t *testing.T) {
	cs := fake.NewClientset()
	if err := DeletePod(context.Background(), cs, "ns1", "missing"); err != nil {
		t.Fatalf("DeletePod on missing pod should be a no-op, got %v", err)
	}
}

func TestDeletePod_RemovesExisting(t *testing.T) {
	cs := fake.NewClientset(reapPod("alive", "laptop", 1234))
	if err := DeletePod(context.Background(), cs, "ns1", "alive"); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if _, err := cs.CoreV1().Pods("ns1").Get(context.Background(), "alive", metav1.GetOptions{}); err == nil {
		t.Fatalf("expected pod to be gone")
	}
}

func TestReapStale_DeadPidIsReapedAlivePidIsKept(t *testing.T) {
	cs := fake.NewClientset(
		reapPod("orphan", "laptop", 100),
		reapPod("running", "laptop", 200),
	)
	alive := func(pid int) bool { return pid == 200 }

	n, err := reapStaleWithLiveness(context.Background(), cs, "ns1", "laptop", alive)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if n != 1 {
		t.Errorf("reaped = %d, want 1", n)
	}
	if _, err := cs.CoreV1().Pods("ns1").Get(context.Background(), "orphan", metav1.GetOptions{}); err == nil {
		t.Errorf("orphan (dead owner-pid) should have been reaped")
	}
	if _, err := cs.CoreV1().Pods("ns1").Get(context.Background(), "running", metav1.GetOptions{}); err != nil {
		t.Errorf("running pod (alive owner-pid) must be left alone: %v", err)
	}
}

// TestReapStale_OwnerHostFilter pins the multi-workstation safety invariant:
// a pod created by a different host must never be touched, even if its owning
// pid is dead from THIS host's perspective.
func TestReapStale_OwnerHostFilter(t *testing.T) {
	cs := fake.NewClientset(
		reapPod("mine", "laptop", 100),
		reapPod("theirs", "other-host", 100),
	)
	allDead := func(int) bool { return false }

	n, err := reapStaleWithLiveness(context.Background(), cs, "ns1", "laptop", allDead)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if n != 1 {
		t.Errorf("reaped = %d, want 1 (only the local-host pod)", n)
	}
	if _, err := cs.CoreV1().Pods("ns1").Get(context.Background(), "theirs", metav1.GetOptions{}); err != nil {
		t.Errorf("other-host pod must be left alone: %v", err)
	}
}

// TestReapStale_MissingOwnerPidLabelIsSkipped surfaces an anomaly without
// touching the pod.
func TestReapStale_MissingOwnerPidLabelIsSkipped(t *testing.T) {
	cs := fake.NewClientset(reapPod("no-pid-label", "laptop", -1)) // pid=-1 means "don't set label"
	allDead := func(int) bool { return false }

	n, err := reapStaleWithLiveness(context.Background(), cs, "ns1", "laptop", allDead)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if n != 0 {
		t.Errorf("reaped = %d, want 0 (anomaly must be surfaced, not reaped)", n)
	}
	if _, err := cs.CoreV1().Pods("ns1").Get(context.Background(), "no-pid-label", metav1.GetOptions{}); err != nil {
		t.Errorf("pod without owner-pid label must be left for activeDeadlineSeconds to handle: %v", err)
	}
}

// TestReapStale_MalformedOwnerPidLabelIsSkipped covers the "owner-pid is
// not parseable as an int" anomaly. Same disposition as missing label: skip
// + log, don't guess.
func TestReapStale_MalformedOwnerPidLabelIsSkipped(t *testing.T) {
	cs := fake.NewClientset(reapPodWithBadPID("garbled", "laptop"))
	allDead := func(int) bool { return false }

	n, err := reapStaleWithLiveness(context.Background(), cs, "ns1", "laptop", allDead)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if n != 0 {
		t.Errorf("reaped = %d, want 0 (malformed pid label must not be reaped)", n)
	}
}

// TestReapStale_ZeroPidIsSkipped — defensive: the owner-pid label is a
// well-formed integer, but its value is 0. kill(0, ...) signals the calling
// process's session, not a specific PID, so we must not treat 0 as a real
// owner.
func TestReapStale_ZeroPidIsSkipped(t *testing.T) {
	cs := fake.NewClientset(reapPod("zero", "laptop", 0))
	allDead := func(int) bool { return false }

	n, err := reapStaleWithLiveness(context.Background(), cs, "ns1", "laptop", allDead)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if n != 0 {
		t.Errorf("reaped = %d, want 0 (pid=0 must not be reaped)", n)
	}
}

// TestReapStale_EmptyHostListsAcrossOwners — when ownerHost is unset, the
// reaper does not narrow by owner-host.
func TestReapStale_EmptyHostListsAcrossOwners(t *testing.T) {
	cs := fake.NewClientset(
		reapPod("a", "host-a", 100),
		reapPod("b", "host-b", 200),
	)
	allDead := func(int) bool { return false }

	n, err := reapStaleWithLiveness(context.Background(), cs, "ns1", "", allDead)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if n != 2 {
		t.Errorf("reaped = %d, want 2", n)
	}
}

// TestProcessAlive_OwnPidIsAlive sanity-checks the OS-backed helper used in
// production. The current test process is definitively alive.
func TestProcessAlive_OwnPidIsAlive(t *testing.T) {
	if !processAlive(os.Getpid()) {
		t.Error("processAlive(os.Getpid()) must return true for the running test process")
	}
}

// TestProcessAlive_ImpossiblePidIsDead picks a PID well above any plausible
// pid_max so syscall.Kill returns ESRCH on every POSIX system.
func TestProcessAlive_ImpossiblePidIsDead(t *testing.T) {
	if processAlive(999999999) {
		t.Error("processAlive(999999999) must return false — pid above any pid_max")
	}
}