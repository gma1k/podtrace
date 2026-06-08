package v1alpha1_test

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
	webhookv1alpha1 "github.com/podtrace/podtrace/internal/webhook/v1alpha1"
)

// TestPodTraceValidator_UpdateUnchangedSpecShortCircuits covers the
// early-return branch in ValidateUpdate: when the spec is unchanged the
// validator must skip revalidation entirely. This is asserted by pointing
// exporterRef at a non-existent ExporterConfig — a metadata-only update
// (e.g. clearing a finalizer) on an otherwise-invalid spec must still be
// allowed so resources never wedge.
func TestPodTraceValidator_UpdateUnchangedSpecShortCircuits(t *testing.T) {
	c := newClientWithExporter(t, "default", "")
	v := &webhookv1alpha1.PodTraceCustomValidator{Client: c}

	spec := podtracev1alpha1.PodTraceSpec{
		Selector:    validSelector(),
		ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ghost"},
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

// TestPodTraceValidator_UpdateNilOldRevalidates covers the branch where
// oldPT is nil: the short-circuit guard is skipped and the new object is
// validated. A valid new object must pass.
func TestPodTraceValidator_UpdateNilOldRevalidates(t *testing.T) {
	c := newClientWithExporter(t, "default", "prod-otlp")
	v := &webhookv1alpha1.PodTraceCustomValidator{Client: c}

	newPT := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: "default"},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    validSelector(),
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "prod-otlp"},
		},
	}
	if _, err := v.ValidateUpdate(context.Background(), nil, newPT); err != nil {
		t.Fatalf("nil-old update with valid spec must pass, got %v", err)
	}
}
