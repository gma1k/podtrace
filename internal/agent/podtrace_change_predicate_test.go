package agent

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func podTraceAt(generation int64, mutate func(*podtracev1alpha1.PodTrace)) *podtracev1alpha1.PodTrace {
	pt := &podtracev1alpha1.PodTrace{ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: "ns", Generation: generation}}
	if mutate != nil {
		mutate(pt)
	}
	return pt
}

func TestPodTraceChangePredicate_IgnoresStatusAndMetadataOnlyUpdates(t *testing.T) {
	p := podTraceChangePredicate()
	old := podTraceAt(3, nil)

	statusOnly := podTraceAt(3, func(pt *podtracev1alpha1.PodTrace) {
		pt.Status.NodeStatus = []podtracev1alpha1.PodTraceNodeStatus{{Node: "n1", Ready: true}}
	})
	if p.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: statusOnly}) {
		t.Error("a status row write must not trigger a rebuild")
	}
	labelsOnly := podTraceAt(3, func(pt *podtracev1alpha1.PodTrace) { pt.Labels = map[string]string{"x": "y"} })
	if p.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: labelsOnly}) {
		t.Error("a label edit must not trigger a rebuild")
	}
}

func TestPodTraceChangePredicate_PassesSpecChangesCreatesAndDeletes(t *testing.T) {
	p := podTraceChangePredicate()
	if !p.Update(event.UpdateEvent{ObjectOld: podTraceAt(3, nil), ObjectNew: podTraceAt(4, nil)}) {
		t.Error("a spec change (new generation) must trigger a rebuild")
	}
	if !p.Create(event.CreateEvent{Object: podTraceAt(1, nil)}) {
		t.Error("a create must trigger a rebuild")
	}
	if !p.Delete(event.DeleteEvent{Object: podTraceAt(1, nil)}) {
		t.Error("a delete must trigger a rebuild")
	}
}
