package agent

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// mkPod builds a minimal Pod fixture. Phase=Running + non-empty label
// map is the "traceable" shape the matcher expects.
func mkPod(namespace, name string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: labels},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func TestMatchPodTraceAgainstPods_SelectorMatch(t *testing.T) {
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "pt"},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
		},
	}
	pods := []*corev1.Pod{
		mkPod("default", "api-a", map[string]string{"app": "api"}),
		mkPod("default", "api-b", map[string]string{"app": "api"}),
		mkPod("default", "worker", map[string]string{"app": "worker"}),
	}
	matched, err := MatchPodTraceAgainstPods(pt, pods)
	if err != nil {
		t.Fatal(err)
	}
	if len(matched) != 2 {
		t.Fatalf("matched=%d want 2", len(matched))
	}
	if matched[0].Name != "api-a" || matched[1].Name != "api-b" {
		t.Errorf("unexpected match order: %+v", matched)
	}
}

func TestMatchPodTraceAgainstPods_PodRefs(t *testing.T) {
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "pt"},
		Spec: podtracev1alpha1.PodTraceSpec{
			PodRefs: []podtracev1alpha1.PodRef{
				{Name: "api-a"},                    // defaults to default ns
				{Namespace: "kube-system", Name: "dns"}, // explicit ns
			},
			NamespaceSelector: &metav1.LabelSelector{}, // allow cross-ns
		},
	}
	pods := []*corev1.Pod{
		mkPod("default", "api-a", nil),
		mkPod("default", "unrelated", nil),
		mkPod("kube-system", "dns", nil),
	}
	matched, err := MatchPodTraceAgainstPods(pt, pods)
	if err != nil {
		t.Fatal(err)
	}
	if len(matched) != 2 {
		t.Fatalf("matched=%d want 2: %+v", len(matched), matched)
	}
}

func TestMatchPodTraceAgainstPods_PausedReturnsNothing(t *testing.T) {
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "pt"},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			Paused:   true,
		},
	}
	pods := []*corev1.Pod{mkPod("default", "api-a", map[string]string{"app": "api"})}
	matched, err := MatchPodTraceAgainstPods(pt, pods)
	if err != nil {
		t.Fatal(err)
	}
	if len(matched) != 0 {
		t.Fatalf("paused PodTrace should match nothing, got %+v", matched)
	}
}

func TestMatchPodTraceAgainstPods_NamespaceScope(t *testing.T) {
	// Without NamespaceSelector the matcher must not return pods from
	// other namespaces — even if labels match.
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "pt"},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
		},
	}
	pods := []*corev1.Pod{
		mkPod("default", "a", map[string]string{"app": "x"}),
		mkPod("other-ns", "b", map[string]string{"app": "x"}),
	}
	matched, err := MatchPodTraceAgainstPods(pt, pods)
	if err != nil {
		t.Fatal(err)
	}
	if len(matched) != 1 || matched[0].Namespace != "default" {
		t.Errorf("namespace scope violated: %+v", matched)
	}
}

func TestMatchPodTraceAgainstPods_OnlyRunningPodsEligible(t *testing.T) {
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "pt"},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
		},
	}
	pending := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "pending", Labels: map[string]string{"app": "x"}},
		Status:     corev1.PodStatus{Phase: corev1.PodPending},
	}
	failed := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "failed", Labels: map[string]string{"app": "x"}},
		Status:     corev1.PodStatus{Phase: corev1.PodFailed},
	}
	running := mkPod("default", "running", map[string]string{"app": "x"})

	matched, err := MatchPodTraceAgainstPods(pt, []*corev1.Pod{pending, failed, running})
	if err != nil {
		t.Fatal(err)
	}
	if len(matched) != 1 || matched[0].Name != "running" {
		t.Fatalf("eligibility filter failed: %+v", matched)
	}
}

func TestMatchPodTraceAgainstPods_EmptySelectorIsUnset(t *testing.T) {
	// A LabelSelector with no MatchLabels and no MatchExpressions must
	// NOT match every pod. Otherwise the webhook's selector-xor-podRefs
	// rule would be silently violated.
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "pt"},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector: &metav1.LabelSelector{}, // empty but non-nil
		},
	}
	pods := []*corev1.Pod{mkPod("default", "a", map[string]string{"app": "x"})}
	matched, err := MatchPodTraceAgainstPods(pt, pods)
	if err != nil {
		t.Fatal(err)
	}
	if len(matched) != 0 {
		t.Errorf("empty selector must not match: %+v", matched)
	}
}

func TestMatchPodTraceAgainstPods_NilPtRejected(t *testing.T) {
	if _, err := MatchPodTraceAgainstPods(nil, nil); err == nil {
		t.Error("expected error on nil PodTrace")
	}
}

func TestMatchPodTraceAgainstPods_HandlesNilPodSlice(t *testing.T) {
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "pt"},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "x"}},
		},
	}
	matched, err := MatchPodTraceAgainstPods(pt, nil)
	if err != nil || len(matched) != 0 {
		t.Errorf("nil pod slice: err=%v matched=%+v", err, matched)
	}
}
