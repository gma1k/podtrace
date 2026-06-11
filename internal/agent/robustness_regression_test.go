package agent

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// TestPodChangePredicates_ContainerRestartTriggers: a container restart
// keeps phase and labels identical but produces a new container ID (and a
// new cgroup inode). The old predicate filtered such updates out, so on a
// quiet node the restarted container's events stayed unroutable forever.
func TestPodChangePredicates_ContainerRestartTriggers(t *testing.T) {
	p := podChangePredicates()

	old := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "x"}},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "main", ContainerID: "containerd://aaa", RestartCount: 0},
			},
		},
	}
	restarted := old.DeepCopy()
	restarted.Status.ContainerStatuses[0].ContainerID = "containerd://bbb"
	restarted.Status.ContainerStatuses[0].RestartCount = 1

	if !p.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: restarted}) {
		t.Error("container restart (new container ID) must trigger a reconcile")
	}
}

// TestPodChangePredicates_PodIPAssignmentTriggers: PodIP often lands after
// the pod is already Running; matching and enrichment need it.
func TestPodChangePredicates_PodIPAssignmentTriggers(t *testing.T) {
	p := podChangePredicates()

	old := &corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	withIP := old.DeepCopy()
	withIP.Status.PodIP = "10.0.0.7"

	if !p.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: withIP}) {
		t.Error("PodIP assignment must trigger a reconcile")
	}
	if p.Update(event.UpdateEvent{ObjectOld: withIP, ObjectNew: withIP.DeepCopy()}) {
		t.Error("identical update must still be filtered out")
	}
}

// TestStatusWriter_RetractsStaleNodeRows: when a CR stops having a rule on
// this node, the agent must apply an empty status under its field owner so
// the SSA map-list drops the row — previously the last written row (often
// Ready=true) lingered on the CR forever.
func TestStatusWriter_RetractsStaleNodeRows(t *testing.T) {
	const ns = "default"
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: ns, UID: "uid-1"},
	}
	rp := &recordingPatcher{}
	c := newRecordingClient(t, rp, pt)

	router := NewRouter(nil)
	key := CRKey{Namespace: ns, Name: "pt"}
	router.Publish([]CRRule{{Key: key, CgroupIDs: map[uint64]struct{}{1: {}}}})

	w := &StatusWriter{Client: c, NodeName: "node-1", Router: router, Ready: func() bool { return true }}
	if err := w.emitOnce(context.Background()); err != nil {
		t.Fatalf("first emit: %v", err)
	}

	router.Publish(nil)
	if err := w.emitOnce(context.Background()); err != nil {
		t.Fatalf("second emit: %v", err)
	}

	calls := rp.snapshot()
	if len(calls) < 2 {
		t.Fatalf("expected a status row apply followed by a retraction, got %d applies", len(calls))
	}
	last := calls[len(calls)-1]
	if last.key.Name != "pt" || last.key.Namespace != ns {
		t.Fatalf("retraction targeted %v, want %s/pt", last.key, ns)
	}
	if len(last.pt.Status.NodeStatus) != 0 {
		t.Errorf("retraction must apply an empty nodeStatus, got %+v", last.pt.Status.NodeStatus)
	}

	before := len(rp.snapshot())
	if err := w.emitOnce(context.Background()); err != nil {
		t.Fatalf("third emit: %v", err)
	}
	if after := len(rp.snapshot()); after != before {
		t.Errorf("idle emit issued %d extra applies, want 0", after-before)
	}
}
