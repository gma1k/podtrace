package operator

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestPodTraceReconcile_DropsRowsOfDeletedNodes(t *testing.T) {
	scheme := newOperatorScheme(t)
	pt := ptMoreTrace(func(pt *podtracev1alpha1.PodTrace) {
		pt.Status.NodeStatus = []podtracev1alpha1.PodTraceNodeStatus{
			{Node: "live", Ready: true, MatchedPods: 2},
			{Node: "gone", Ready: false, MatchedPods: 5, Message: "attach failed"},
		}
	})
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(pt, ptMoreExporterConfig(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "live"}}).Build()
	r := &PodTraceReconciler{Client: c, Scheme: scheme, SystemNamespace: ptMoreSysNS}
	if _, err := ptMoreReconcile(t, r); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var got podtracev1alpha1.PodTrace
	if err := c.Get(context.Background(), types.NamespacedName{Name: "pt", Namespace: "default"}, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Status.NodeStatus) != 1 || got.Status.NodeStatus[0].Node != "live" {
		t.Fatalf("nodeStatus = %+v, want only the row of the node that still exists", got.Status.NodeStatus)
	}
	if got.Status.MatchedPods != 2 {
		t.Errorf("matchedPods = %d, want 2 (the deleted node's 5 no longer counted)", got.Status.MatchedPods)
	}
	if deg := findCondition(got.Status.Conditions, ConditionDegraded); deg == nil || deg.Status != metav1.ConditionFalse {
		t.Errorf("Degraded = %+v, want False once the deleted node's degraded row is gone", deg)
	}
	if ready := findCondition(got.Status.Conditions, ConditionReady); ready == nil || ready.Status != metav1.ConditionTrue {
		t.Errorf("Ready = %+v, want True from the one live node", ready)
	}
}

func TestDeletedNodeToPodTraces_EnqueuesOnlyCRsWithARowForTheNode(t *testing.T) {
	scheme := newOperatorScheme(t)
	withRow := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "with-row", Namespace: "a"},
		Status:     podtracev1alpha1.PodTraceStatus{NodeStatus: []podtracev1alpha1.PodTraceNodeStatus{{Node: "gone"}}},
	}
	withoutRow := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "without-row", Namespace: "b"},
		Status:     podtracev1alpha1.PodTraceStatus{NodeStatus: []podtracev1alpha1.PodTraceNodeStatus{{Node: "live"}}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&podtracev1alpha1.PodTrace{}).
		WithObjects(withRow, withoutRow).Build()
	r := &PodTraceReconciler{Client: c, Scheme: scheme}

	reqs := r.deletedNodeToPodTraces(context.Background(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "gone"}})
	if len(reqs) != 1 || reqs[0].Name != "with-row" || reqs[0].Namespace != "a" {
		t.Errorf("requests = %+v, want only a/with-row", reqs)
	}
}

func TestDropRowsOfDeletedNodes_KeepsRowsWhenTheLookupFails(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
				return errors.New("apiserver unavailable")
			},
		}).Build()
	r := &PodTraceReconciler{Client: c, Scheme: scheme}
	rows := []podtracev1alpha1.PodTraceNodeStatus{{Node: "n1"}, {Node: "n2"}}
	if got := r.dropRowsOfDeletedNodes(context.Background(), rows); len(got) != 2 {
		t.Errorf("kept %d rows, want both: only NotFound proves a node is gone", len(got))
	}
}

func TestNodeDeletedPredicate_PassesOnlyDeletes(t *testing.T) {
	p := nodeDeletedPredicate()
	n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}}
	if p.Create(event.CreateEvent{Object: n}) || p.Update(event.UpdateEvent{ObjectOld: n, ObjectNew: n}) || p.Generic(event.GenericEvent{Object: n}) {
		t.Error("only a Node delete can leave a stale row")
	}
	if !p.Delete(event.DeleteEvent{Object: n}) {
		t.Error("a Node delete must enqueue the PodTraces with its rows")
	}
}

func TestDeletedNodeToPodTraces_ListFailureEnqueuesNothing(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
				return errors.New("apiserver unavailable")
			},
		}).Build()
	r := &PodTraceReconciler{Client: c, Scheme: scheme}
	if reqs := r.deletedNodeToPodTraces(context.Background(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "gone"}}); len(reqs) != 0 {
		t.Errorf("requests = %+v, want none", reqs)
	}
}
