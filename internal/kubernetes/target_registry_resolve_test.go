package kubernetes

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/podtrace/podtrace/internal/config"
)

func TestEnqueueUpsert_RecordsPodAndSignals(t *testing.T) {
	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{})
	pod := runningPod("uid-enq", "ns", "p", "app", hex64())

	tr.enqueueUpsert(pod)

	tr.pendingMu.Lock()
	_, ok := tr.pending[pod.UID]
	n := len(tr.pending)
	tr.pendingMu.Unlock()
	if !ok || n != 1 {
		t.Fatalf("expected pod recorded in pending (n=%d, ok=%v)", n, ok)
	}

	select {
	case <-tr.pendingCh:
	default:
		t.Error("expected pendingCh to be signalled after enqueueUpsert")
	}
}

func TestEnqueueUpsert_IgnoresNonPod(t *testing.T) {
	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{})
	tr.enqueueUpsert("not-a-pod")
	tr.enqueueUpsert((*corev1.Pod)(nil))

	tr.pendingMu.Lock()
	n := len(tr.pending)
	tr.pendingMu.Unlock()
	if n != 0 {
		t.Errorf("expected no pending entries for non-pod input, got %d", n)
	}
}

func TestResolveWorker_DrainsAndResolves(t *testing.T) {
	cid := hex64()
	newCgroupV2Sandbox(t, cid)

	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{Namespaces: []string{"prod"}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tr.resolveWorker(ctx)

	pod := runningPod("uid-worker", "prod", "api-0", "app", cid)
	tr.enqueueUpsert(pod)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		tr.mu.RLock()
		_, ok := tr.targets[pod.UID]
		tr.mu.RUnlock()
		if ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("resolveWorker did not resolve the enqueued pod within the deadline")
}

func TestResolvePodInfoFromObject_FallbackIDsOnly(t *testing.T) {

	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "cgroup.controllers"), []byte("cpu memory\n"), 0o644); err != nil {
		t.Fatalf("write cgroup.controllers: %v", err)
	}
	origBase := config.CgroupBasePath
	config.CgroupBasePath = base
	t.Setenv("PODTRACE_CRI_RESOLVE", "false")
	t.Cleanup(func() { config.CgroupBasePath = origBase })

	cid := hex64()
	pod := runningPod("uid-fallback", "ns", "p", "app", cid)

	info, err := resolvePodInfoFromObject(context.Background(), pod, "")
	if err != nil {
		t.Fatalf("expected fallback (IDs-only) success, got error: %v", err)
	}
	if info.ContainerID != cid {
		t.Errorf("expected container ID %q, got %q", cid, info.ContainerID)
	}
	if info.CgroupPath != "" {
		t.Errorf("expected empty cgroup path in IDs-only fallback, got %q", info.CgroupPath)
	}
	if len(info.Containers) != 1 || info.Containers[0].CgroupPath != "" {
		t.Errorf("expected one container target with no cgroup, got %+v", info.Containers)
	}
}

func TestResolvePodInfoFromObject_NoUsableContainer(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "uid-nu", Namespace: "ns", Name: "p"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c0"}}},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "c0", ContainerID: "garbage-no-scheme",
					State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}},
			},
		},
	}
	_, err := resolvePodInfoFromObject(context.Background(), pod, "")
	if err == nil || !strings.Contains(err.Error(), "no usable container") {
		t.Errorf("expected 'no usable container' error, got: %v", err)
	}
}

func TestPodHasContainerID(t *testing.T) {
	pod := &corev1.Pod{
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{ContainerID: "containerd://abc123def456abc"},
			},
		},
	}
	if podHasContainerID(pod, "") {
		t.Error("empty shortID must never match")
	}
	if !podHasContainerID(pod, "abc123def456abc") {
		t.Error("expected a match on the schemed container ID")
	}
	if podHasContainerID(pod, "unrelated0000") {
		t.Error("did not expect a match for an unrelated ID")
	}
}

func TestMatchesSelection_PodRefNamespaceMismatch(t *testing.T) {
	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{Pods: []string{"ns-a/pod-1"}})
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns-b", Name: "pod-1"}}
	if tr.matchesSelection(pod) {
		t.Error("pod in an unreferenced namespace must not match")
	}
}
