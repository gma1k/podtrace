package operator

import (
	"context"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func podsArg(args []string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--pods" {
			return args[i+1]
		}
	}
	return ""
}

func scheduledPod(name, node string, phase corev1.PodPhase) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "team-a"},
		Spec:       corev1.PodSpec{NodeName: node},
		Status:     corev1.PodStatus{Phase: phase},
	}
}

func TestForNodeKeepsRefsBoundToTheNodeAndRefsWithNoNode(t *testing.T) {
	targets := sessionTargets{
		PodRefs: []podtracev1alpha1.PodRef{
			{Name: "on-a"}, {Name: "on-b"}, {Name: "unscheduled"}, {Namespace: "team-b", Name: "on-a"},
		},
		PodRefNodes: map[string]string{
			"team-a/on-a": "node-a",
			"team-a/on-b": "node-b",
			"team-b/on-a": "node-b",
		},
	}
	got := targets.forNode("team-a", "node-a").PodRefs
	want := []podtracev1alpha1.PodRef{{Name: "on-a"}, {Name: "unscheduled"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("node-a refs = %v, want %v", got, want)
	}
	if len(targets.PodRefs) != 4 {
		t.Fatalf("forNode mutated the session-wide refs: %v", targets.PodRefs)
	}
}

func TestForNodeWithoutPlacementsKeepsEveryRef(t *testing.T) {
	targets := sessionTargets{PodRefs: []podtracev1alpha1.PodRef{{Name: "a"}, {Name: "b"}}}
	if got := targets.forNode("team-a", "node-a").PodRefs; !reflect.DeepEqual(got, targets.PodRefs) {
		t.Fatalf("refs = %v", got)
	}
}

func TestResolveSessionTargetsRecordsWhereEachRefIsBound(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		scheduledPod("web-0", "node-a", corev1.PodRunning),
		scheduledPod("web-1", "node-b", corev1.PodRunning),
		scheduledPod("starting", "node-b", corev1.PodPending),
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "unscheduled", Namespace: "team-a"}},
	).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme}
	s := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s", Namespace: "team-a"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			PodRefs: []podtracev1alpha1.PodRef{
				{Name: "web-0"}, {Name: "web-1"}, {Name: "starting"}, {Name: "unscheduled"}, {Name: "gone"},
			},
		},
	}
	out, err := r.resolveSessionTargets(context.Background(), s)
	if err != nil {
		t.Fatalf("resolveSessionTargets: %v", err)
	}
	want := map[string]string{"team-a/web-0": "node-a", "team-a/web-1": "node-b", "team-a/starting": "node-b"}
	if !reflect.DeepEqual(out.PodRefNodes, want) {
		t.Fatalf("PodRefNodes = %v, want %v", out.PodRefNodes, want)
	}
	if !reflect.DeepEqual(out.Nodes, []string{"node-a", "node-b"}) {
		t.Fatalf("Nodes = %v", out.Nodes)
	}
}

func TestEachNodeJobOnlyTargetsPodRefsThatCanRunThere(t *testing.T) {
	scheme := newOperatorScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		scheduledPod("web-0", "node-a", corev1.PodRunning),
		scheduledPod("web-1", "node-b", corev1.PodRunning),
	).Build()
	r := &PodTraceSessionReconciler{Client: c, Scheme: scheme}
	s := minimalSession()
	s.Namespace = "team-a"
	s.Spec.PodRefs = []podtracev1alpha1.PodRef{{Name: "web-0"}, {Name: "web-1"}, {Name: "gone"}}
	targets, err := r.resolveSessionTargets(context.Background(), s)
	if err != nil {
		t.Fatalf("resolveSessionTargets: %v", err)
	}

	want := map[string]string{
		"node-a": "team-a/web-0,team-a/gone",
		"node-b": "team-a/web-1,team-a/gone",
	}
	for node, pods := range want {
		spec := buildSessionJobSpec(s, nil, node, targets)
		if got := podsArg(spec.Template.Spec.Containers[0].Args); got != pods {
			t.Errorf("%s Job --pods = %q, want %q", node, got, pods)
		}
	}
}
