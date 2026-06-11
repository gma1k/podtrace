package operator

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

// TestSecretWatchMapsToReferencingCRs covers the Secret→CR mappers behind
// the new Secret watches: bundle Secrets are copies of the referenced
// credential data, so rotating a Secret must enqueue exactly the PodTraces
// and non-terminal PodTraceSessions whose ExporterConfig references it.
func TestSecretWatchMapsToReferencingCRs(t *testing.T) {
	scheme := newOperatorScheme(t)

	rotated := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "otlp-creds", Namespace: "default"}}
	unrelated := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "other-creds", Namespace: "default"}}

	referencingEC := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ec-with-secret", Namespace: "default"},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{
				Endpoint:          "collector:4318",
				HeadersFromSecret: &podtracev1alpha1.LocalObjectReference{Name: "otlp-creds"},
			},
		},
	}
	plainEC := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "ec-plain", Namespace: "default"},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "collector:4318"},
		},
	}

	tracedPT := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt-secret", Namespace: "default"},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "a"}},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec-with-secret"},
		},
	}
	plainPT := &podtracev1alpha1.PodTrace{
		ObjectMeta: metav1.ObjectMeta{Name: "pt-plain", Namespace: "default"},
		Spec: podtracev1alpha1.PodTraceSpec{
			Selector:    &metav1.LabelSelector{MatchLabels: map[string]string{"app": "b"}},
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec-plain"},
		},
	}

	activeSession := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s-active", Namespace: "default"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec-with-secret"},
		},
		Status: podtracev1alpha1.PodTraceSessionStatus{State: podtracev1alpha1.SessionStateRunning},
	}
	doneSession := &podtracev1alpha1.PodTraceSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s-done", Namespace: "default"},
		Spec: podtracev1alpha1.PodTraceSessionSpec{
			ExporterRef: podtracev1alpha1.LocalObjectReference{Name: "ec-with-secret"},
		},
		Status: podtracev1alpha1.PodTraceSessionStatus{State: podtracev1alpha1.SessionStateCompleted},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(rotated, unrelated, referencingEC, plainEC, tracedPT, plainPT, activeSession, doneSession).
		Build()

	ptr := &PodTraceReconciler{Client: c, Scheme: scheme}
	reqs := ptr.secretToPodTraces(context.Background(), rotated)
	if len(reqs) != 1 || reqs[0].Name != "pt-secret" {
		t.Errorf("secretToPodTraces(otlp-creds) = %v, want exactly pt-secret", reqs)
	}
	if reqs := ptr.secretToPodTraces(context.Background(), unrelated); len(reqs) != 0 {
		t.Errorf("secretToPodTraces(other-creds) = %v, want none", reqs)
	}

	str := &PodTraceSessionReconciler{Client: c, Scheme: scheme}
	sreqs := str.secretToPodTraceSessions(context.Background(), rotated)
	if len(sreqs) != 1 || sreqs[0].Name != "s-active" {
		t.Errorf("secretToPodTraceSessions(otlp-creds) = %v, want exactly the active session (terminal ones skipped)", sreqs)
	}
	if sreqs := str.secretToPodTraceSessions(context.Background(), unrelated); len(sreqs) != 0 {
		t.Errorf("secretToPodTraceSessions(other-creds) = %v, want none", sreqs)
	}
}
