package agent

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func TestBuildSelectors_AppSelectorInvalidExpressionErrors(t *testing.T) {
	pt := &podtracev1alpha1.PodTrace{
		Spec: podtracev1alpha1.PodTraceSpec{
			AppSelector: &podtracev1alpha1.AppSelector{
				MatchSelectors: []metav1.LabelSelector{
					{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{Key: "app", Operator: "TotallyBogusOperator", Values: []string{"x"}},
						},
					},
				},
			},
		},
	}

	if _, err := buildSelectors(pt); err == nil {
		t.Fatal("expected buildSelectors to reject an invalid match-expression operator")
	}
}

func TestMatchPodTraceAgainstPods_PropagatesSelectorError(t *testing.T) {
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pt"},
		Spec: podtracev1alpha1.PodTraceSpec{
			AppSelector: &podtracev1alpha1.AppSelector{
				MatchSelectors: []metav1.LabelSelector{
					{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{Key: "app", Operator: "NopeNotAnOperator", Values: []string{"x"}},
						},
					},
				},
			},
		},
	}
	pods := []*corev1.Pod{{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "p", Labels: map[string]string{"app": "x"}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}}

	_, err := MatchPodTraceAgainstPods(pt, pods, nil)
	if err == nil {
		t.Fatal("expected selector-build error to propagate from MatchPodTraceAgainstPods")
	}
	if !strings.Contains(err.Error(), "operator") {
		t.Errorf("error should describe the invalid operator, got: %v", err)
	}
}

func TestMatchPodTraceAgainstPods_AppSelectorUnionMatches(t *testing.T) {
	pt := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pt"},
		Spec: podtracev1alpha1.PodTraceSpec{
			AppSelector: &podtracev1alpha1.AppSelector{
				MatchSelectors: []metav1.LabelSelector{
					{MatchLabels: map[string]string{"tier": "frontend"}},
					{MatchLabels: map[string]string{"tier": "backend"}},
				},
			},
		},
	}
	pods := []*corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "fe", Labels: map[string]string{"tier": "frontend"}},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "be", Labels: map[string]string{"tier": "backend"}},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "other", Labels: map[string]string{"tier": "cache"}},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		},
	}

	matched, err := MatchPodTraceAgainstPods(pt, pods, nil)
	if err != nil {
		t.Fatalf("MatchPodTraceAgainstPods: %v", err)
	}
	if len(matched) != 2 {
		t.Fatalf("union selector matched %d pods, want 2 (frontend + backend)", len(matched))
	}
}
