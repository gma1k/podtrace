package agent

import (
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/gma1k/podtrace/internal/events"
)

func TestEnricher_LookupHitAndMiss(t *testing.T) {
	e := NewPodEnricher()

	if _, ok := e.Lookup(42); ok {
		t.Fatal("empty enricher must miss every lookup")
	}
	if s := e.Stats(); s.Hits != 0 || s.Misses != 1 {
		t.Errorf("after one miss: hits=%d misses=%d (want 0/1)", s.Hits, s.Misses)
	}

	pod := newPodWithOwner("ns", "p", "u1", "n", "Deployment", "web", "web-7d8c9c")
	e.Snapshot([]PodCgroupEntry{
		{CgroupID: 42, Pod: pod, ContainerName: "app"},
	})

	meta, ok := e.Lookup(42)
	if !ok {
		t.Fatal("after snapshot, cgroup 42 must hit")
	}
	want := events.K8sMetadata{
		Namespace:     "ns",
		PodName:       "p",
		PodUID:        "u1",
		NodeName:      "n",
		ContainerName: "app",
		WorkloadKind:  "Deployment",
		WorkloadName:  "web",
	}
	if meta != want {
		t.Errorf("Lookup metadata = %+v, want %+v", meta, want)
	}
}

func TestEnricher_SnapshotEvicts(t *testing.T) {
	e := NewPodEnricher()
	first := newPodWithOwner("ns", "old", "u-old", "n", "Deployment", "web", "web-aaaaaa")
	second := newPodWithOwner("ns", "new", "u-new", "n", "Deployment", "api", "api-bbbbbb")

	e.Snapshot([]PodCgroupEntry{{CgroupID: 9001, Pod: first}})
	if meta, _ := e.Lookup(9001); meta.PodUID != "u-old" {
		t.Fatalf("first snapshot did not register: %+v", meta)
	}

	e.Snapshot([]PodCgroupEntry{{CgroupID: 9001, Pod: second}})
	meta, ok := e.Lookup(9001)
	if !ok || meta.PodUID != "u-new" {
		t.Errorf("reused cgroup must return new pod's metadata, got %+v ok=%v", meta, ok)
	}

	e.Snapshot([]PodCgroupEntry{})
	if _, ok := e.Lookup(9001); ok {
		t.Error("empty snapshot must evict every entry")
	}
}

func TestEnricher_OrphanCountedSeparately(t *testing.T) {
	e := NewPodEnricher()
	owned := newPodWithOwner("ns", "p", "u", "n", "Deployment", "web", "web-aaaaaa")
	orphan := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "static", UID: "uo"}}
	e.Snapshot([]PodCgroupEntry{
		{CgroupID: 1, Pod: owned},
		{CgroupID: 2, Pod: orphan},
	})
	s := e.Stats()
	if s.OwnerResolved != 1 || s.OwnerOrphaned != 1 {
		t.Errorf("owner counters: resolved=%d orphaned=%d (want 1/1)", s.OwnerResolved, s.OwnerOrphaned)
	}
}

func TestEnricher_NilSafe(t *testing.T) {
	var e *PodEnricher
	if _, ok := e.Lookup(1); ok {
		t.Error("nil Lookup must miss")
	}
	e.Snapshot([]PodCgroupEntry{{CgroupID: 1}})
	if got := e.Size(); got != 0 {
		t.Errorf("nil Size = %d, want 0", got)
	}
	enrichBatch(nil, []*events.Event{{CgroupID: 1}})
}

func TestEnrichBatch_PointerSharedAcrossEvents(t *testing.T) {
	e := NewPodEnricher()
	pod := newPodWithOwner("ns", "p", "u", "n", "Deployment", "web", "web-aaaaaa")
	e.Snapshot([]PodCgroupEntry{{CgroupID: 7, Pod: pod}})

	batch := []*events.Event{
		{CgroupID: 7},
		{CgroupID: 7},
		{CgroupID: 99},
		{CgroupID: 7},
	}
	enrichBatch(e, batch)

	if batch[0].K8s == nil || batch[1].K8s != batch[0].K8s || batch[3].K8s != batch[0].K8s {
		t.Error("events sharing a cgroup ID must share the metadata pointer")
	}
	if batch[2].K8s != nil {
		t.Errorf("miss must leave K8s nil, got %+v", batch[2].K8s)
	}
}

func TestEnrichBatch_PreservesExistingK8s(t *testing.T) {
	e := NewPodEnricher()
	pod := newPodWithOwner("ns", "p", "u-cache", "n", "Deployment", "web", "web-aaaaaa")
	e.Snapshot([]PodCgroupEntry{{CgroupID: 7, Pod: pod}})

	pre := &events.K8sMetadata{PodUID: "u-upstream"}
	batch := []*events.Event{{CgroupID: 7, K8s: pre}}
	enrichBatch(e, batch)

	if batch[0].K8s != pre {
		t.Errorf("pre-stamped K8s must be preserved, got %+v", batch[0].K8s)
	}
}

func TestEnricher_ConcurrentLookupSnapshot(t *testing.T) {
	e := NewPodEnricher()
	pod := newPodWithOwner("ns", "p", "u", "n", "Deployment", "web", "web-aaaaaa")

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				_, _ = e.Lookup(uint64(j % 64))
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			entries := make([]PodCgroupEntry, 0, 32)
			for j := 0; j < 32; j++ {
				entries = append(entries, PodCgroupEntry{CgroupID: uint64(j), Pod: pod})
			}
			e.Snapshot(entries)
		}
	}()
	wg.Wait()
}

func newPodWithOwner(namespace, podName, uid, node, ownerKind, deploymentName, rsName string) *corev1.Pod {
	tc := true
	if ownerKind == "Deployment" {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace, Name: podName, UID: types.UID(uid),
				OwnerReferences: []metav1.OwnerReference{
					{Kind: "ReplicaSet", Name: rsName, Controller: &tc},
				},
			},
			Spec: corev1.PodSpec{NodeName: node},
		}
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace, Name: podName, UID: types.UID(uid),
			OwnerReferences: []metav1.OwnerReference{
				{Kind: ownerKind, Name: deploymentName, Controller: &tc},
			},
		},
		Spec: corev1.PodSpec{NodeName: node},
	}
}
