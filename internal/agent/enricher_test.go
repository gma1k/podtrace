package agent

import (
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/podtrace/podtrace/internal/events"
)

// Owner-walk tests document the v1 contract for resolveWorkload: the
// only rollup is ReplicaSet to Deployment, every other controller kind
// is reported as-is, and pods with no controller owner degrade to
// kind=Pod.
func TestResolveWorkload(t *testing.T) {
	tcontroller := true
	notController := false

	cases := []struct {
		name     string
		pod      *corev1.Pod
		wantKind string
		wantName string
	}{
		{
			name: "no owners → orphan pod degrades to Pod",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "lonely"},
			},
			wantKind: "Pod",
			wantName: "lonely",
		},
		{
			name: "owner ref present but not controller → orphan",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "free-pod",
					OwnerReferences: []metav1.OwnerReference{
						{Kind: "ReplicaSet", Name: "rs-7d8c9c", Controller: &notController},
					},
				},
			},
			wantKind: "Pod",
			wantName: "free-pod",
		},
		{
			name: "ReplicaSet with valid hash suffix rolls up to Deployment",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "p-1",
					OwnerReferences: []metav1.OwnerReference{
						{Kind: "ReplicaSet", Name: "shopping-cart-7d8c9c", Controller: &tcontroller},
					},
				},
			},
			wantKind: "Deployment",
			wantName: "shopping-cart",
		},
		{
			name: "ReplicaSet without recognisable hash → no rollup",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "p-2",
					OwnerReferences: []metav1.OwnerReference{
						{Kind: "ReplicaSet", Name: "rs-without-hash", Controller: &tcontroller},
					},
				},
			},
			wantKind: "ReplicaSet",
			wantName: "rs-without-hash",
		},
		{
			name: "StatefulSet → reported as-is",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{
						{Kind: "StatefulSet", Name: "kafka", Controller: &tcontroller},
					},
				},
			},
			wantKind: "StatefulSet",
			wantName: "kafka",
		},
		{
			name: "DaemonSet → reported as-is",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{
						{Kind: "DaemonSet", Name: "fluentd", Controller: &tcontroller},
					},
				},
			},
			wantKind: "DaemonSet",
			wantName: "fluentd",
		},
		{
			name: "Job → reported as-is",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{
						{Kind: "Job", Name: "nightly-backup-29543", Controller: &tcontroller},
					},
				},
			},
			wantKind: "Job",
			wantName: "nightly-backup-29543",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, name := resolveWorkload(tc.pod)
			if kind != tc.wantKind || name != tc.wantName {
				t.Errorf("resolveWorkload = (%q, %q), want (%q, %q)",
					kind, name, tc.wantKind, tc.wantName)
			}
		})
	}
}

// TestDeploymentFromReplicaSet pins the suffix-trim behaviour.
func TestDeploymentFromReplicaSet(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"shopping-cart-7d8c9c", "shopping-cart", true},
		{"webapp-58b6f7c9d4", "webapp", true},
		{"a-bcdfg", "a", true},
		{"single", "", false},
		{"trailing-", "", false},
		{"my-rs-prod", "", false},
		{"deploy-toolong-suffixabcdefgh", "", false},
		{"deploy-9c", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := deploymentFromReplicaSet(tc.in)
			if got != tc.want || ok != tc.wantOK {
				t.Errorf("deploymentFromReplicaSet(%q) = (%q, %v), want (%q, %v)",
					tc.in, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// TestEnricher_LookupHitAndMiss covers the documented behaviour: an
// unseen cgroup ID is a miss (zero value, false), a snapshotted one
// is a hit, and counters move in the right direction.
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

// TestEnricher_SnapshotEvicts is the critical correctness guarantee:
// after a pod delete the cache must not serve stale metadata for the
// reused cgroup ID.
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

// TestEnricher_OrphanCountedSeparately verifies the owner-resolution
// counter discriminates between resolved and orphaned pods.
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

// TestEnricher_NilSafe documents the explicit nil-safety guarantees:
// nil enricher must never panic on Lookup, Snapshot, or Size, and
// nil-pointer event-stamping is a no-op.
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

// TestEnrichBatch_PointerSharedAcrossEvents verifies the hot-path
// memoization: events with the same cgroup ID get the same metadata
// pointer rather than per-event copies.
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

// TestEnrichBatch_PreservesExistingK8s pins the contract that an
// upstream producer (a future enricher in front of the router) can
// stamp metadata before the router sees the event and the router
// will not overwrite it.
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

// TestEnricher_ConcurrentLookupSnapshot exercises the documented
// thread-safety contract: many concurrent Lookups must coexist with
// Snapshot writes without races (-race catches map mutation here).
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

// newPodWithOwner constructs a Pod whose OwnerReferences exercise the
// ReplicaSet to Deployment rollup helper.
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