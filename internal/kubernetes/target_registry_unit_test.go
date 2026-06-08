package kubernetes

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/podtrace/podtrace/internal/config"
)

// newCgroupV2Sandbox builds a temporary cgroup-v2 tree containing a kubepods
// subdirectory for the given container ID and points config.CgroupBasePath at
// it for the duration of the test. It also disables CRI resolution so
// resolvePodInfoFromObject falls through to the filesystem walk. It returns the
// full cgroup path that findCgroupPathV2 is expected to discover.
func newCgroupV2Sandbox(t *testing.T, containerID string) string {
	t.Helper()

	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "cgroup.controllers"), []byte("cpu memory\n"), 0o644); err != nil {
		t.Fatalf("write cgroup.controllers: %v", err)
	}
	cgDir := filepath.Join(base, "kubepods.slice", "container-"+containerID)
	if err := os.MkdirAll(cgDir, 0o755); err != nil {
		t.Fatalf("mkdir cgroup dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cgDir, "cgroup.procs"), []byte(""), 0o644); err != nil {
		t.Fatalf("write cgroup.procs: %v", err)
	}

	origBase := config.CgroupBasePath
	config.CgroupBasePath = base
	t.Setenv("PODTRACE_CRI_RESOLVE", "false")
	t.Cleanup(func() { config.CgroupBasePath = origBase })

	return cgDir
}

// runningPod returns a pod whose single container is fully populated so that
// resolvePodInfoFromObject can succeed (valid 64-char hex container ID).
func runningPod(uid, ns, name, containerName, containerID string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			UID:       types.UID(uid),
			Namespace: ns,
			Name:      name,
			Labels:    map[string]string{"app": "demo"},
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "ReplicaSet", Name: name + "-rs"},
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: containerName}},
		},
		Status: corev1.PodStatus{
			PodIP: "10.1.2.3",
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: containerName, ContainerID: "containerd://" + containerID},
			},
		},
	}
}

func TestResolvePodInfoFromObject_SuccessExtractsFields(t *testing.T) {
	cid := hex64()
	wantCgroup := newCgroupV2Sandbox(t, cid)

	pod := runningPod("uid-1", "prod", "api-0", "app", cid)

	info, err := resolvePodInfoFromObject(context.Background(), pod, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("expected non-nil PodInfo")
	}
	if info.PodName != "api-0" {
		t.Errorf("PodName: got %q want %q", info.PodName, "api-0")
	}
	if info.Namespace != "prod" {
		t.Errorf("Namespace: got %q want %q", info.Namespace, "prod")
	}
	if info.ContainerID != cid {
		t.Errorf("ContainerID: got %q want %q", info.ContainerID, cid)
	}
	if info.ContainerName != "app" {
		t.Errorf("ContainerName: got %q want %q", info.ContainerName, "app")
	}
	if info.PodIP != "10.1.2.3" {
		t.Errorf("PodIP: got %q want %q", info.PodIP, "10.1.2.3")
	}
	if info.OwnerKind != "ReplicaSet" || info.OwnerName != "api-0-rs" {
		t.Errorf("owner: got %q/%q want ReplicaSet/api-0-rs", info.OwnerKind, info.OwnerName)
	}
	if info.Labels["app"] != "demo" {
		t.Errorf("Labels: got %v want app=demo", info.Labels)
	}
	if info.CgroupPath != wantCgroup {
		t.Errorf("CgroupPath: got %q want %q", info.CgroupPath, wantCgroup)
	}
}

func TestResolvePodInfoFromObject_NamedContainerSelected(t *testing.T) {
	cid := hex64()
	newCgroupV2Sandbox(t, cid)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "uid-named", Namespace: "ns", Name: "p"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "sidecar"}, {Name: "main"}},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "sidecar", ContainerID: "containerd://" + hex64()},
				{Name: "main", ContainerID: "containerd://" + cid},
			},
		},
	}

	info, err := resolvePodInfoFromObject(context.Background(), pod, "main")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ContainerID != cid {
		t.Errorf("ContainerID: got %q want %q (wrong container selected)", info.ContainerID, cid)
	}
	if info.ContainerName != "main" {
		t.Errorf("ContainerName: got %q want main", info.ContainerName)
	}
}

func TestResolvePodInfoFromObject_MissingOptionalFields(t *testing.T) {
	cid := hex64()
	newCgroupV2Sandbox(t, cid)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: "uid-min", Namespace: "ns", Name: "bare"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "c0"}},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "c0", ContainerID: "containerd://" + cid},
			},
		},
	}

	info, err := resolvePodInfoFromObject(context.Background(), pod, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.OwnerKind != "" || info.OwnerName != "" {
		t.Errorf("expected empty owner, got %q/%q", info.OwnerKind, info.OwnerName)
	}
	if info.PodIP != "" {
		t.Errorf("expected empty PodIP, got %q", info.PodIP)
	}
	if len(info.Labels) != 0 {
		t.Errorf("expected empty labels, got %v", info.Labels)
	}
}

func TestHandlePodUpsert_InsertsMatchingPod(t *testing.T) {
	cid := hex64()
	newCgroupV2Sandbox(t, cid)

	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{Namespaces: []string{"prod"}})
	pod := runningPod("uid-ins", "prod", "api-0", "app", cid)

	tr.handlePodUpsert(pod)

	tr.mu.RLock()
	got, ok := tr.targets[pod.UID]
	tr.mu.RUnlock()
	if !ok {
		t.Fatal("matching pod was not inserted into targets")
	}
	if got.PodName != "api-0" || got.ContainerID != cid {
		t.Fatalf("stored PodInfo unexpected: %+v", got)
	}

	snap := tr.Snapshot()
	if len(snap) != 1 || snap[0].PodName != "api-0" {
		t.Fatalf("snapshot did not reflect inserted pod: %+v", snap)
	}
}

func TestHandlePodUpsert_RespectsMaxTargets(t *testing.T) {
	cid := hex64()
	newCgroupV2Sandbox(t, cid)

	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{})
	tr.maxTargets = 1
	tr.targets[types.UID("existing")] = &PodInfo{PodName: "existing"}

	pod := runningPod("uid-overflow", "ns", "newpod", "app", cid)
	tr.handlePodUpsert(pod)

	tr.mu.RLock()
	_, inserted := tr.targets[pod.UID]
	count := len(tr.targets)
	tr.mu.RUnlock()
	if inserted {
		t.Fatal("new pod should be rejected when max targets reached")
	}
	if count != 1 {
		t.Fatalf("target count: got %d want 1", count)
	}
}

func TestHandlePodUpsert_UpdatesExistingAtMaxTargets(t *testing.T) {
	cid := hex64()
	newCgroupV2Sandbox(t, cid)

	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{})
	tr.maxTargets = 1

	pod := runningPod("uid-upd", "ns", "p", "app", cid)
	tr.targets[pod.UID] = &PodInfo{PodName: "stale"}

	tr.handlePodUpsert(pod)

	tr.mu.RLock()
	got := tr.targets[pod.UID]
	tr.mu.RUnlock()
	if got == nil || got.PodName != "p" {
		t.Fatalf("existing target should be updated at max limit, got %+v", got)
	}
}

func TestRebuildFromStore_PopulatesFromInformerStore(t *testing.T) {
	cid := hex64()
	newCgroupV2Sandbox(t, cid)

	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{Namespaces: []string{"prod"}})

	factory := informers.NewSharedInformerFactory(tr.clientset, 0)
	tr.podInf = factory.Core().V1().Pods().Informer()

	matching := runningPod("uid-a", "prod", "api-0", "app", cid)
	nonMatching := runningPod("uid-b", "dev", "api-1", "app", hex64())
	if err := tr.podInf.GetStore().Add(matching); err != nil {
		t.Fatalf("store add matching: %v", err)
	}
	if err := tr.podInf.GetStore().Add(nonMatching); err != nil {
		t.Fatalf("store add non-matching: %v", err)
	}

	tr.rebuildFromStore()

	tr.mu.RLock()
	_, hasMatch := tr.targets[matching.UID]
	_, hasNonMatch := tr.targets[nonMatching.UID]
	count := len(tr.targets)
	tr.mu.RUnlock()

	if !hasMatch {
		t.Error("matching pod from store was not added to targets")
	}
	if hasNonMatch {
		t.Error("non-matching pod (wrong namespace) must not be added")
	}
	if count != 1 {
		t.Fatalf("target count: got %d want 1", count)
	}
}

func TestRebuildFromStore_NoInformerIsNoop(t *testing.T) {
	tr := NewTargetRegistry(fake.NewSimpleClientset(), TargetSelection{})
	tr.rebuildFromStore()
	if len(tr.targets) != 0 {
		t.Fatalf("expected no targets, got %d", len(tr.targets))
	}
}
