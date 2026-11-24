package kubernetes

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/gma1k/podtrace/internal/config"
)

func containerIDFor(i int) string {
	return fmt.Sprintf("%064x", i+1)
}

func newMultiCgroupSandbox(t *testing.T, ids ...string) string {
	t.Helper()
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "cgroup.controllers"), []byte("cpu memory\n"), 0o644); err != nil {
		t.Fatalf("write cgroup.controllers: %v", err)
	}
	for _, id := range ids {
		dir := filepath.Join(base, "kubepods.slice", "container-"+id)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(""), 0o644); err != nil {
			t.Fatalf("write cgroup.procs: %v", err)
		}
	}
	orig := config.CgroupBasePath
	config.CgroupBasePath = base
	t.Setenv("PODTRACE_CRI_RESOLVE", "false")
	t.Cleanup(func() { config.CgroupBasePath = orig })
	return base
}

func podOnNode(i int, node string) *corev1.Pod {
	pod := runningPod(fmt.Sprintf("uid-%d", i), "shop", fmt.Sprintf("web-%d", i), "app", containerIDFor(i))
	pod.Spec.NodeName = node
	return pod
}

func TestMatcherRejectsPodsOnOtherNodesWhenTheSelectionNamesANode(t *testing.T) {
	matches, err := TargetSelection{NodeName: "node-a"}.Matcher()
	if err != nil {
		t.Fatal(err)
	}
	if !matches(podOnNode(0, "node-a")) {
		t.Error("a pod on the selection's node must match")
	}
	if matches(podOnNode(1, "node-b")) {
		t.Error("a pod on another node must not match")
	}
	if matches(podOnNode(2, "")) {
		t.Error("an unscheduled pod must not match a node-scoped selection")
	}
	unscoped, _ := TargetSelection{}.Matcher()
	if !unscoped(podOnNode(3, "node-b")) {
		t.Error("a selection without a node must keep pods on any node")
	}
}

func TestTargetListOptionsCarryTheNodeFieldSelector(t *testing.T) {
	opts := metav1.ListOptions{}
	targetListOptions(TargetSelection{PodSelector: "app=web", NodeName: "node-a"})(&opts)
	if opts.LabelSelector != "app=web" || opts.FieldSelector != "spec.nodeName=node-a" {
		t.Fatalf("options = %+v, want the label selector and spec.nodeName=node-a", opts)
	}
	opts = metav1.ListOptions{}
	targetListOptions(TargetSelection{})(&opts)
	if opts.LabelSelector != "" || opts.FieldSelector != "" {
		t.Fatalf("options = %+v, want no selectors for an unscoped selection", opts)
	}
}

func TestANodeScopedRegistryTracesItsLocalPodsWhenOffNodePodsExceedTheCap(t *testing.T) {
	const offNode = 300
	ids := []string{containerIDFor(offNode)}
	objects := make([]runtime.Object, 0, offNode+1)
	for i := 0; i < offNode; i++ {
		objects = append(objects, podOnNode(i, "node-b"))
	}
	objects = append(objects, podOnNode(offNode, "node-a"))
	newMultiCgroupSandbox(t, ids...)

	cs := fake.NewClientset(objects...)
	var fieldSelectors []string
	cs.PrependReactor("list", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		fieldSelectors = append(fieldSelectors, a.(k8stesting.ListActionImpl).ListOptions.FieldSelector)
		return false, nil, nil
	})
	tr := NewTargetRegistry(cs, TargetSelection{Namespaces: []string{"shop"}, AllInNamespace: true, NodeName: "node-a"})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := tr.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	snap := tr.Snapshot()
	if len(snap) != 1 || snap[0].PodName != fmt.Sprintf("web-%d", offNode) {
		names := make([]string, 0, len(snap))
		for _, p := range snap {
			names = append(names, p.PodName)
		}
		t.Fatalf("targets = %v, want only the local pod", names)
	}
	if len(fieldSelectors) == 0 || !strings.Contains(fieldSelectors[0], "spec.nodeName=node-a") {
		t.Fatalf("pod LIST field selectors = %q, want spec.nodeName=node-a", fieldSelectors)
	}
}

func TestAStatusUpdateThatChangesNothingAttachedDoesNotResolveOrRepublish(t *testing.T) {
	id := containerIDFor(0)
	base := newMultiCgroupSandbox(t, id)
	tr := NewTargetRegistry(fake.NewClientset(), TargetSelection{})
	pod := runningPod("uid-steady", "shop", "web", "app", id)
	if !tr.upsertPod(context.Background(), pod) {
		t.Fatal("first upsert must publish")
	}
	if err := os.RemoveAll(filepath.Join(base, "kubepods.slice")); err != nil {
		t.Fatal(err)
	}

	flipped := pod.DeepCopy()
	flipped.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse}}
	if tr.upsertPod(context.Background(), flipped) {
		t.Fatal("a readiness flip must not republish the target set")
	}
	if got := tr.Snapshot()[0]; got.CgroupPath == "" {
		t.Fatal("the target was resolved again instead of reusing its cgroup")
	}

	relabelled := pod.DeepCopy()
	relabelled.Labels = map[string]string{"app": "demo", "version": "v2"}
	relabelled.Status.PodIP = "10.9.9.9"
	if !tr.upsertPod(context.Background(), relabelled) {
		t.Fatal("a label or IP change must republish")
	}
	got := tr.Snapshot()[0]
	if got.Labels["version"] != "v2" || got.PodIP != "10.9.9.9" || got.CgroupPath == "" {
		t.Fatalf("refreshed target = %+v, want new labels and IP on the kept cgroup", got)
	}
}

func TestRefreshResolvedTargetResolvesAgainWhenTheContainersChanged(t *testing.T) {
	id := containerIDFor(0)
	current := &PodInfo{Containers: []ContainerTarget{{Name: "app", ID: id, CgroupPath: "/cg/" + id}}}

	pod := runningPod("uid-r", "shop", "web", "app", id)
	if _, ok := refreshResolvedTarget(current, pod, ""); !ok {
		t.Fatal("the same running container must be reused")
	}

	restarted := runningPod("uid-r", "shop", "web", "app", containerIDFor(1))
	if _, ok := refreshResolvedTarget(current, restarted, ""); ok {
		t.Error("a restarted container must be resolved again")
	}

	renamed := runningPod("uid-r", "shop", "web", "other", id)
	if _, ok := refreshResolvedTarget(current, renamed, ""); ok {
		t.Error("a container under another name must be resolved again")
	}

	added := runningPod("uid-r", "shop", "web", "app", id)
	added.Status.ContainerStatuses = append(added.Status.ContainerStatuses, corev1.ContainerStatus{
		Name: "sidecar", ContainerID: "containerd://" + containerIDFor(2),
		State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
	})
	if _, ok := refreshResolvedTarget(current, added, ""); ok {
		t.Error("a new container must be resolved again")
	}

	stopped := runningPod("uid-r", "shop", "web", "app", id)
	stopped.Status.ContainerStatuses[0].State = corev1.ContainerState{}
	if _, ok := refreshResolvedTarget(current, stopped, ""); ok {
		t.Error("a pod with no running container must be resolved again")
	}

	badID := runningPod("uid-r", "shop", "web", "app", "not-hex")
	if _, ok := refreshResolvedTarget(current, badID, ""); ok {
		t.Error("an unparseable container ID must be resolved again")
	}

	partial := &PodInfo{Containers: []ContainerTarget{{Name: "app", ID: id}}}
	if _, ok := refreshResolvedTarget(partial, pod, ""); ok {
		t.Error("a container without a cgroup must get another resolution")
	}
}

func TestPodInfoEqualComparesEveryPublishedField(t *testing.T) {
	base := func() *PodInfo {
		return &PodInfo{
			PodName: "p", Namespace: "n", ContainerID: "c", CgroupPath: "/cg", ContainerName: "app",
			PodIP: "10.0.0.1", OwnerKind: "Deployment", OwnerName: "web",
			Containers: []ContainerTarget{{Name: "app", ID: "c", CgroupPath: "/cg"}},
			Labels:     map[string]string{"a": "1"},
		}
	}
	if !podInfoEqual(base(), base()) {
		t.Fatal("identical infos must be equal")
	}
	mutations := map[string]func(*PodInfo){
		"pod ip":          func(p *PodInfo) { p.PodIP = "10.0.0.2" },
		"owner":           func(p *PodInfo) { p.OwnerName = "api" },
		"container count": func(p *PodInfo) { p.Containers = nil },
		"container":       func(p *PodInfo) { p.Containers[0].CgroupPath = "/other" },
		"label count":     func(p *PodInfo) { p.Labels["b"] = "2" },
		"label value":     func(p *PodInfo) { p.Labels["a"] = "2" },
		"label key":       func(p *PodInfo) { p.Labels = map[string]string{"z": "1"} },
	}
	for name, mutate := range mutations {
		changed := base()
		mutate(changed)
		if podInfoEqual(base(), changed) {
			t.Errorf("%s change must not compare equal", name)
		}
	}
}

func TestStoreTargetIgnoresAPodDeletedWhileItResolved(t *testing.T) {
	tr := NewTargetRegistry(fake.NewClientset(), TargetSelection{})
	pod := runningPod("uid-gone", "shop", "web", "app", containerIDFor(0))
	tr.deleted[pod.UID] = time.Now()
	if tr.storeTarget(pod, &PodInfo{PodName: "web"}) {
		t.Fatal("a deleted pod must not be stored")
	}
	if tr.upsertPod(context.Background(), pod) {
		t.Fatal("a deleted pod must not be upserted")
	}
	if len(tr.Snapshot()) != 0 {
		t.Fatal("a deleted pod reappeared in the target set")
	}
}

func TestStoreTargetHonoursACapThatFilledWhileThePodResolved(t *testing.T) {
	tr := NewTargetRegistry(fake.NewClientset(), TargetSelection{})
	tr.maxTargets = 1
	tr.targets[types.UID("other")] = &PodInfo{PodName: "other"}
	pod := runningPod("uid-late", "shop", "web", "app", containerIDFor(0))
	if tr.storeTarget(pod, &PodInfo{PodName: "web"}) {
		t.Fatal("a pod must not exceed the cap")
	}
	if _, waiting := tr.capped[pod.UID]; !waiting {
		t.Fatal("a pod turned away at the cap must wait for a free slot")
	}
}
