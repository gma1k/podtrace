package v1alpha1_test

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
	webhookv1alpha1 "github.com/gma1k/podtrace/internal/webhook/v1alpha1"
)

func TestPodTraceValidator_UpdateUnchangedSpecShortCircuits(t *testing.T) {
	c := newClientWithExporter(t, "default", "")
	v := &webhookv1alpha1.PodTraceCustomValidator{Client: c}

	spec := podtracev1alpha1.PodTraceSpec{
		Selector:    validSelector(),
		ExporterRef: corev1.LocalObjectReference{Name: "ghost"},
	}
	oldPT := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "pt", Namespace: "default",
			Finalizers: []string{"podtrace.io/cleanup"},
		},
		Spec: spec,
	}
	newPT := oldPT.DeepCopy()
	newPT.Finalizers = nil

	if _, err := v.ValidateUpdate(context.Background(), oldPT, newPT); err != nil {
		t.Fatalf("unchanged-spec update must short-circuit and pass, got %v", err)
	}
}

func TestPodTraceValidator_UpdateNilOldRevalidates(t *testing.T) {
	c := newClientWithExporter(t, "default", "prod-otlp")
	v := &webhookv1alpha1.PodTraceCustomValidator{Client: c}

	newPT := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: "default"},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    validSelector(),
			ExporterRef: corev1.LocalObjectReference{Name: "prod-otlp"},
		},
	}
	if _, err := v.ValidateUpdate(context.Background(), nil, newPT); err != nil {
		t.Fatalf("nil-old update with valid spec must pass, got %v", err)
	}
}
