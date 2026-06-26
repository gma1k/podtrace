package agent

import (
	"strings"
	"sync"
	"sync/atomic"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/podtrace/podtrace/internal/events"
)

// PodEnricher maps kernel cgroup inode IDs to a frozen, six-attribute
// Kubernetes metadata bundle used to enrich exported spans.
type PodEnricher struct {
	mu    sync.RWMutex
	byCgroup map[uint64]events.K8sMetadata

	hits           atomic.Int64
	misses         atomic.Int64
	snapshots      atomic.Int64
	ownerResolved  atomic.Int64
	ownerOrphaned  atomic.Int64
}

// NewPodEnricher returns an empty enricher.
func NewPodEnricher() *PodEnricher {
	return &PodEnricher{
		byCgroup: map[uint64]events.K8sMetadata{},
	}
}

// Lookup returns the metadata for cgroupID and whether it was found.
func (e *PodEnricher) Lookup(cgroupID uint64) (events.K8sMetadata, bool) {
	if e == nil {
		return events.K8sMetadata{}, false
	}
	e.mu.RLock()
	meta, ok := e.byCgroup[cgroupID]
	e.mu.RUnlock()
	if ok {
		e.hits.Add(1)
	} else {
		e.misses.Add(1)
	}
	return meta, ok
}

// Snapshot atomically replaces the cache with metas.
func (e *PodEnricher) Snapshot(entries []PodCgroupEntry) {
	if e == nil {
		return
	}
	next := make(map[uint64]events.K8sMetadata, len(entries))
	seenPods := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry.Pod == nil {
			continue
		}
		next[entry.CgroupID] = buildK8sMetadata(entry)

		// Owner resolution is tallied once per unique pod (UID), not
		// once per entry — a pod with N container cgroups must not
		// inflate the counter N-fold. Pods with no UID (synthetic
		// test fixtures) are skipped for the counter only.
		uid := string(entry.Pod.UID)
		if uid == "" {
			continue
		}
		if _, dup := seenPods[uid]; dup {
			continue
		}
		seenPods[uid] = struct{}{}
		if controllerOwnerRef(entry.Pod.OwnerReferences) == nil {
			e.ownerOrphaned.Add(1)
		} else {
			e.ownerResolved.Add(1)
		}
	}
	e.mu.Lock()
	e.byCgroup = next
	e.mu.Unlock()
	e.snapshots.Add(1)
}

// Size returns the number of cached cgroup IDs. Used by the metrics
// refresh path and tests.
func (e *PodEnricher) Size() int {
	if e == nil {
		return 0
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.byCgroup)
}

// EnricherStats is the read-only snapshot the metrics path consumes.
type EnricherStats struct {
	Hits          int64
	Misses        int64
	Snapshots     int64
	OwnerResolved int64
	OwnerOrphaned int64
	CacheSize     int
}

// Stats returns the counters atomically. Safe to call concurrently
// with Lookup and Snapshot.
func (e *PodEnricher) Stats() EnricherStats {
	if e == nil {
		return EnricherStats{}
	}
	return EnricherStats{
		Hits:          e.hits.Load(),
		Misses:        e.misses.Load(),
		Snapshots:     e.snapshots.Load(),
		OwnerResolved: e.ownerResolved.Load(),
		OwnerOrphaned: e.ownerOrphaned.Load(),
		CacheSize:     e.Size(),
	}
}

// enrichBatch stamps each event in batch with its matching
// K8sMetadata.
func enrichBatch(e *PodEnricher, batch []*events.Event) {
	if e == nil {
		return
	}
	var memo map[uint64]*events.K8sMetadata
	for _, ev := range batch {
		if ev == nil || ev.K8s != nil {
			continue
		}
		if memo == nil {
			memo = make(map[uint64]*events.K8sMetadata, 8)
		}
		if cached, ok := memo[ev.CgroupID]; ok {
			ev.K8s = cached
			continue
		}
		meta, found := e.Lookup(ev.CgroupID)
		if !found {
			memo[ev.CgroupID] = nil
			continue
		}
		m := meta
		memo[ev.CgroupID] = &m
		ev.K8s = &m
	}
}

// PodCgroupEntry is the unit of input to PodEnricher.Snapshot.
type PodCgroupEntry struct {
	CgroupID      uint64
	CgroupPath    string
	Pod           *corev1.Pod
	ContainerName string
	ContainerID   string
	ContainerPID uint32
}

// buildK8sMetadata projects a PodCgroupEntry onto the frozen v1
// metadata schema.
func buildK8sMetadata(entry PodCgroupEntry) events.K8sMetadata {
	pod := entry.Pod
	meta := events.K8sMetadata{
		Namespace:     pod.Namespace,
		PodName:       pod.Name,
		PodUID:        string(pod.UID),
		NodeName:      pod.Spec.NodeName,
		ContainerName: entry.ContainerName,
	}
	kind, name := resolveWorkload(pod)
	meta.WorkloadKind = kind
	meta.WorkloadName = name
	return meta
}

// resolveWorkload walks pod.OwnerReferences and returns the
// (kind, name) of the workload that ultimately produced this pod.
func resolveWorkload(pod *corev1.Pod) (kind, name string) {
	owner := controllerOwnerRef(pod.OwnerReferences)
	if owner == nil {
		return "Pod", pod.Name
	}
	if owner.Kind == "ReplicaSet" {
		if deployment, ok := deploymentFromReplicaSet(owner.Name); ok {
			return "Deployment", deployment
		}
		return "ReplicaSet", owner.Name
	}
	return owner.Kind, owner.Name
}

// controllerOwnerRef returns the OwnerReference flagged as the
// controller.
func controllerOwnerRef(refs []metav1.OwnerReference) *metav1.OwnerReference {
	for i := range refs {
		ref := &refs[i]
		if ref.Controller != nil && *ref.Controller {
			return ref
		}
	}
	return nil
}

// deploymentFromReplicaSet strips the kubernetes-controller-manager
// pod-template-hash suffix from a ReplicaSet name.
func deploymentFromReplicaSet(rsName string) (string, bool) {
	idx := strings.LastIndex(rsName, "-")
	if idx < 1 || idx == len(rsName)-1 {
		return "", false
	}
	suffix := rsName[idx+1:]
	if !isPodTemplateHash(suffix) {
		return "", false
	}
	return rsName[:idx], true
}

// isPodTemplateHash matches the alphabet kube-controller-manager
// uses for the ReplicaSet pod-template-hash suffix.
func isPodTemplateHash(s string) bool {
	if len(s) < 5 || len(s) > 12 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c == 'b', c == 'c', c == 'd':
		case c == 'f', c == 'g', c == 'h':
		case c == 'j', c == 'k', c == 'm', c == 'n':
		case c >= 'p' && c <= 't':
		case c == 'v', c == 'w', c == 'x', c == 'y', c == 'z':
		default:
			return false
		}
	}
	return true
}