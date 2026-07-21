package agent

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestEnricher_SnapshotSkipsNilPod(t *testing.T) {
	e := NewPodEnricher()
	real := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "p", UID: "u1"}}
	e.Snapshot([]PodCgroupEntry{
		{CgroupID: 1, Pod: nil},
		{CgroupID: 2, Pod: real},
	})

	if _, ok := e.Lookup(1); ok {
		t.Error("nil-pod entry must not populate the cache")
	}
	if _, ok := e.Lookup(2); !ok {
		t.Error("valid entry must populate the cache")
	}
	if s := e.Stats(); s.CacheSize != 1 {
		t.Errorf("CacheSize = %d, want 1 (nil pod excluded)", s.CacheSize)
	}
}

func TestEnricher_SnapshotSkipsOwnerCountForEmptyUID(t *testing.T) {
	e := NewPodEnricher()
	noUID := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "synthetic"}}
	e.Snapshot([]PodCgroupEntry{{CgroupID: 7, Pod: noUID}})

	if _, ok := e.Lookup(7); !ok {
		t.Error("UID-less pod should still be cached for enrichment")
	}
	s := e.Stats()
	if s.OwnerResolved != 0 || s.OwnerOrphaned != 0 {
		t.Errorf("UID-less pod must not touch owner counters: resolved=%d orphaned=%d", s.OwnerResolved, s.OwnerOrphaned)
	}
}

func TestEnricher_SnapshotDeduplicatesOwnerCountByUID(t *testing.T) {
	e := NewPodEnricher()
	orphan := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "p", UID: "same-uid"}}
	e.Snapshot([]PodCgroupEntry{
		{CgroupID: 1, Pod: orphan, ContainerName: "a"},
		{CgroupID: 2, Pod: orphan, ContainerName: "b"},
		{CgroupID: 3, Pod: orphan, ContainerName: "c"},
	})
	if s := e.Stats(); s.OwnerOrphaned != 1 {
		t.Errorf("orphaned tally = %d, want 1 (deduplicated by UID across 3 cgroups)", s.OwnerOrphaned)
	}
	if s := e.Stats(); s.CacheSize != 3 {
		t.Errorf("CacheSize = %d, want 3 (one per container cgroup)", s.CacheSize)
	}
}
