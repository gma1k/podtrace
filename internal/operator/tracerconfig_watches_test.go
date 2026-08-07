package operator

import (
	"context"
	"sort"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func requestNames(t *testing.T, r *TracerConfigReconciler, obj client.Object) []string {
	t.Helper()
	reqs := r.enqueueAllTracerConfigs(context.Background(), obj)
	names := make([]string, 0, len(reqs))
	for _, req := range reqs {
		if req.Namespace != "" {
			t.Errorf("TracerConfig is cluster-scoped; request carried namespace %q", req.Namespace)
		}
		names = append(names, req.Name)
	}
	sort.Strings(names)
	return names
}

func TestEnqueueAllTracerConfigsFansOutToEveryFleet(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		fleetConfig(DefaultTracerConfigName, podtracev1alpha1.TracerConfigSpec{}),
		fleetConfig("regulated", podtracev1alpha1.TracerConfigSpec{}),
		fleetConfig("gpu", podtracev1alpha1.TracerConfigSpec{}),
	).Build()
	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}

	got := requestNames(t, r, fleetNode("n1", nil))

	want := []string{"default", "gpu", "regulated"}
	if len(got) != len(want) {
		t.Fatalf("enqueued %v, want %v: one config's spec change can flip another's Conflict condition", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("enqueued %v, want %v", got, want)
			break
		}
	}
}

func TestEnqueueAllTracerConfigsEmptyCluster(t *testing.T) {
	scheme := newOperatorScheme(t)
	r := &TracerConfigReconciler{
		Client:          fake.NewClientBuilder().WithScheme(scheme).Build(),
		Scheme:          scheme,
		SystemNamespace: "podtrace-system",
	}

	if got := requestNames(t, r, fleetNode("n1", nil)); len(got) != 0 {
		t.Errorf("no configs means nothing to enqueue, got %v", got)
	}
}

func TestEnqueueAllTracerConfigsFallsBackWhenListFails(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, list client.ObjectList, _ ...client.ListOption) error {
				if _, ok := list.(*podtracev1alpha1.TracerConfigList); ok {
					return errInternal()
				}
				return nil
			},
		}).Build()
	r := &TracerConfigReconciler{Client: c, Scheme: scheme, SystemNamespace: "podtrace-system"}

	got := requestNames(t, r, fleetNode("n1", nil))

	if len(got) != 1 || got[0] != DefaultTracerConfigName {
		t.Errorf("a failed list must still enqueue %q rather than drop the event, got %v",
			DefaultTracerConfigName, got)
	}
}

func nodeUpdate(oldNode, newNode *corev1.Node) event.UpdateEvent {
	return event.UpdateEvent{ObjectOld: oldNode, ObjectNew: newNode}
}

func taintedNode(name string, labels map[string]string, taints ...corev1.Taint) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Spec:       corev1.NodeSpec{Taints: taints},
	}
}

func TestNodePredicateDropsStatusOnlyUpdates(t *testing.T) {
	p := nodeSchedulingChangedPredicate()

	before := taintedNode("n1", map[string]string{"pool": "a"})
	after := before.DeepCopy()
	after.Status.Conditions = []corev1.NodeCondition{{
		Type: corev1.NodeReady, Status: corev1.ConditionTrue, Reason: "KubeletReady",
	}}
	after.Status.Allocatable = corev1.ResourceList{}

	if p.Update(nodeUpdate(before, after)) {
		t.Error("kubelet rewrites node status every few seconds; admitting those would requeue every TracerConfig on every heartbeat")
	}
}

func TestNodePredicateAdmitsSchedulingChanges(t *testing.T) {
	p := nodeSchedulingChangedPredicate()

	cases := []struct {
		name           string
		before, after  *corev1.Node
		wantAdmitted   bool
		failureMessage string
	}{
		{
			name:           "label added",
			before:         taintedNode("n1", nil),
			after:          taintedNode("n1", map[string]string{"pool": "a"}),
			wantAdmitted:   true,
			failureMessage: "a new label can move the node into a fleet",
		},
		{
			name:           "label value changed",
			before:         taintedNode("n1", map[string]string{"pool": "a"}),
			after:          taintedNode("n1", map[string]string{"pool": "b"}),
			wantAdmitted:   true,
			failureMessage: "a relabel can move the node between fleets",
		},
		{
			name:           "label removed",
			before:         taintedNode("n1", map[string]string{"pool": "a"}),
			after:          taintedNode("n1", nil),
			wantAdmitted:   true,
			failureMessage: "removing a label can drop the node out of a fleet",
		},
		{
			name:   "taint added",
			before: taintedNode("n1", map[string]string{"pool": "a"}),
			after: taintedNode("n1", map[string]string{"pool": "a"},
				corev1.Taint{Key: "dedicated", Effect: corev1.TaintEffectNoSchedule}),
			wantAdmitted:   true,
			failureMessage: "an untolerated taint excludes the node from its fleet",
		},
		{
			name: "taint removed",
			before: taintedNode("n1", map[string]string{"pool": "a"},
				corev1.Taint{Key: "dedicated", Effect: corev1.TaintEffectNoSchedule}),
			after:          taintedNode("n1", map[string]string{"pool": "a"}),
			wantAdmitted:   true,
			failureMessage: "removing a taint can bring the node back into a fleet",
		},
		{
			name:           "nothing scheduling-relevant changed",
			before:         taintedNode("n1", map[string]string{"pool": "a"}),
			after:          taintedNode("n1", map[string]string{"pool": "a"}),
			wantAdmitted:   false,
			failureMessage: "an identical node must not requeue anything",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := p.Update(nodeUpdate(tt.before, tt.after)); got != tt.wantAdmitted {
				t.Errorf("admitted = %v, want %v: %s", got, tt.wantAdmitted, tt.failureMessage)
			}
		})
	}
}

func TestNodePredicateAdmitsNonNodeObjects(t *testing.T) {
	p := nodeSchedulingChangedPredicate()

	notANode := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p1"}}
	if !p.Update(event.UpdateEvent{ObjectOld: notANode, ObjectNew: notANode}) {
		t.Error("a non-Node object must fail open rather than be silently dropped")
	}
}

func TestNodePredicateAdmitsCreateAndDelete(t *testing.T) {
	p := nodeSchedulingChangedPredicate()
	n := taintedNode("n1", map[string]string{"pool": "a"})

	if !p.Create(event.CreateEvent{Object: n}) {
		t.Error("a new node may belong to a fleet, so creation must requeue")
	}
	if !p.Delete(event.DeleteEvent{Object: n}) {
		t.Error("a removed node changes matchedNodes, so deletion must requeue")
	}
}

func TestStaleAgentSelectorsScopePerFleet(t *testing.T) {
	defaults := staleAgentSelectors(DefaultTracerConfigName)
	if len(defaults) != 2 {
		t.Errorf("the default fleet needs its own selector plus one for unlabelled pre-multi-config leftovers, got %d", len(defaults))
	}

	others := staleAgentSelectors("regulated")
	if len(others) != 1 {
		t.Errorf("a non-default fleet must only ever match its own label, got %d selectors", len(others))
	}
}
