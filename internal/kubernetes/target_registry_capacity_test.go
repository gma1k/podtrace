package kubernetes

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

func startedRegistry(t *testing.T, maxTargets int, pods ...*corev1.Pod) (*TargetRegistry, context.CancelFunc) {
	t.Helper()
	t.Setenv("PODTRACE_MAX_TARGET_PODS", "")
	cs := fake.NewClientset()
	for _, p := range pods {
		if _, err := cs.CoreV1().Pods(p.Namespace).Create(context.Background(), p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	tr := NewTargetRegistry(cs, TargetSelection{Namespaces: []string{"shop"}, PodSelector: "app=demo"})
	tr.maxTargets = maxTargets
	ctx, cancel := context.WithCancel(context.Background())
	if err := tr.Start(ctx); err != nil {
		cancel()
		t.Fatalf("Start: %v", err)
	}
	return tr, cancel
}

func waitForTargets(t *testing.T, tr *TargetRegistry, want func([]*PodInfo) bool) []*PodInfo {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		snap := tr.Snapshot()
		if want(snap) {
			return snap
		}
		if time.Now().After(deadline) {
			t.Fatalf("targets never reached the wanted state, last %d", len(snap))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func hasPod(snap []*PodInfo, name string) bool {
	for _, p := range snap {
		if p.PodName == name {
			return true
		}
	}
	return false
}

func TestAPodTurnedAwayAtTheCapIsTracedOnceATargetIsDeleted(t *testing.T) {
	newMultiCgroupSandbox(t, containerIDFor(0), containerIDFor(1))
	first := podOnNode(0, "node-a")
	second := podOnNode(1, "node-a")
	tr, cancel := startedRegistry(t, 1, first, second)
	defer cancel()

	snap := tr.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("targets = %d, want the cap of 1", len(snap))
	}
	held, waiting := first, second
	if snap[0].PodName == second.Name {
		held, waiting = second, first
	}
	tr.mu.RLock()
	_, isCapped := tr.capped[waiting.UID]
	tr.mu.RUnlock()
	if !isCapped {
		t.Fatal("the pod over the cap must be remembered")
	}

	if err := tr.clientset.CoreV1().Pods(held.Namespace).Delete(context.Background(), held.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitForTargets(t, tr, func(s []*PodInfo) bool { return len(s) == 1 && hasPod(s, waiting.Name) })
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	if len(tr.capped) != 0 {
		t.Fatalf("capped = %v, want empty once the waiting pod became a target", tr.capped)
	}
}

func heldAndWaiting(tr *TargetRegistry, a, b *corev1.Pod) (string, string) {
	if tr.Snapshot()[0].PodName == a.Name {
		return a.Name, b.Name
	}
	return b.Name, a.Name
}

func TestAPodTurnedAwayAtTheCapIsTracedOnceATargetStopsMatching(t *testing.T) {
	newMultiCgroupSandbox(t, containerIDFor(0), containerIDFor(1))
	first := podOnNode(0, "node-a")
	second := podOnNode(1, "node-a")
	tr, cancel := startedRegistry(t, 1, first, second)
	defer cancel()

	held, waiting := heldAndWaiting(tr, first, second)
	pods := tr.clientset.CoreV1().Pods("shop")
	pod, err := pods.Get(context.Background(), held, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pod.Labels = map[string]string{"app": "retired"}
	if _, err := pods.Update(context.Background(), pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitForTargets(t, tr, func(s []*PodInfo) bool { return len(s) == 1 && hasPod(s, waiting) })
}

func TestAPodTurnedAwayAtTheCapIsTracedOnceAStaleTargetIsDropped(t *testing.T) {
	newMultiCgroupSandbox(t, containerIDFor(0), containerIDFor(1))
	first := podOnNode(0, "node-a")
	second := podOnNode(1, "node-a")
	tr, cancel := startedRegistry(t, 1, first, second)
	defer cancel()

	held, waiting := heldAndWaiting(tr, first, second)
	pods := tr.clientset.CoreV1().Pods("shop")
	pod, err := pods.Get(context.Background(), held, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pod.Status.ContainerStatuses = nil
	if _, err := pods.UpdateStatus(context.Background(), pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitForTargets(t, tr, func(s []*PodInfo) bool { return len(s) == 1 && hasPod(s, waiting) })
}

func TestRequeueCappedForgetsPodsThatLeftTheInformer(t *testing.T) {
	tr, cancel := startedRegistry(t, 1)
	defer cancel()
	tr.mu.Lock()
	tr.capped[types.UID("vanished")] = "shop/vanished"
	tr.mu.Unlock()
	tr.requeueCapped()
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	if _, kept := tr.capped["vanished"]; kept {
		t.Fatal("a capped pod no longer in any informer must be forgotten")
	}
}

func TestRequeueCappedRetriesAPodRecreatedUnderTheSameName(t *testing.T) {
	newMultiCgroupSandbox(t, containerIDFor(0))
	pod := podOnNode(0, "node-a")
	tr, cancel := startedRegistry(t, 1)
	defer cancel()
	if err := tr.podInfs[0].GetStore().Add(pod); err != nil {
		t.Fatal(err)
	}
	tr.mu.Lock()
	tr.capped[types.UID("old-uid")] = pod.Namespace + "/" + pod.Name
	tr.mu.Unlock()
	tr.requeueCapped()
	tr.pendingMu.Lock()
	_, queued := tr.pending[pod.UID]
	tr.pendingMu.Unlock()
	tr.mu.RLock()
	_, oldKept := tr.capped["old-uid"]
	tr.mu.RUnlock()
	if oldKept {
		t.Error("the replaced pod's UID must be forgotten")
	}
	if !queued && !hasPod(tr.Snapshot(), pod.Name) {
		t.Error("the recreated pod must be retried")
	}
}

func TestCachedPodSkipsObjectsThatAreNotPods(t *testing.T) {
	tr := NewTargetRegistry(fake.NewClientset(), TargetSelection{})
	store := cache.NewIndexer(func(obj interface{}) (string, error) { return "shop/web", nil }, cache.Indexers{})
	if err := store.Add("not a pod"); err != nil {
		t.Fatal(err)
	}
	tr.podInfs = []cache.SharedIndexInformer{indexerOnlyInformer{SharedIndexInformer: nil, indexer: store}}
	if tr.cachedPod("shop/web") != nil {
		t.Fatal("a non-pod object must not be returned as a pod")
	}
}

type indexerOnlyInformer struct {
	cache.SharedIndexInformer
	indexer cache.Indexer
}

func (i indexerOnlyInformer) GetStore() cache.Store { return i.indexer }
