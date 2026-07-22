package operator

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func TestRenderBundlePayload_SynthesizeSpansStamped(t *testing.T) {
	enabled := true
	spec := otlpSpec(&podtracev1alpha1.OTLPExporter{Endpoint: "collector:4318"})
	spec.SynthesizeSpans = &enabled
	data, _, _, err := renderBundlePayload(nil, ec("otlp-synth", spec), nil)
	if err != nil {
		t.Fatalf("renderBundlePayload: %v", err)
	}
	if data["synthesize_spans"] != "true" {
		t.Errorf("synthesize_spans = %q, want true", data["synthesize_spans"])
	}
}

func TestRenderBundlePayload_SynthesizeSpansDisabledOmitsKey(t *testing.T) {
	disabled := false
	spec := otlpSpec(&podtracev1alpha1.OTLPExporter{Endpoint: "collector:4318"})
	spec.SynthesizeSpans = &disabled
	data, _, _, err := renderBundlePayload(nil, ec("otlp-nosynth", spec), nil)
	if err != nil {
		t.Fatalf("renderBundlePayload: %v", err)
	}
	if _, ok := data["synthesize_spans"]; ok {
		t.Errorf("synthesize_spans key must be absent when disabled, got %q", data["synthesize_spans"])
	}
}

func TestRenderBundlePayload_HeadersFromSecretReturned(t *testing.T) {
	_, _, headersFrom, err := renderBundlePayload(nil, ec("otlp-hfs", otlpSpec(&podtracev1alpha1.OTLPExporter{
		Endpoint:          "collector:4318",
		HeadersFromSecret: &podtracev1alpha1.LocalObjectReference{Name: "extra-headers"},
	})), nil)
	if err != nil {
		t.Fatalf("renderBundlePayload: %v", err)
	}
	if headersFrom == nil || headersFrom.Name != "extra-headers" {
		t.Errorf("headersFrom = %+v, want name=extra-headers", headersFrom)
	}
}

func TestRenderBundlePayload_HeadersFromSecretEmptyNameIgnored(t *testing.T) {
	_, _, headersFrom, err := renderBundlePayload(nil, ec("otlp-hfs-empty", otlpSpec(&podtracev1alpha1.OTLPExporter{
		Endpoint:          "collector:4318",
		HeadersFromSecret: &podtracev1alpha1.LocalObjectReference{Name: ""},
	})), nil)
	if err != nil {
		t.Fatalf("renderBundlePayload: %v", err)
	}
	if headersFrom != nil {
		t.Errorf("empty HeadersFromSecret name must yield nil, got %+v", headersFrom)
	}
}

func TestBuildBundleSecretData_CredentialKeyMissing(t *testing.T) {
	cred := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "auth", Namespace: "user-ns"},
		Data:       map[string][]byte{"other": []byte("x")},
	}
	c := fake.NewClientBuilder().WithObjects(cred).Build()

	if _, err := buildBundleSecretData(context.Background(), c, "user-ns",
		&podtracev1alpha1.SecretKeySelector{Name: "auth", Key: "token"}, nil); err == nil {
		t.Fatal("expected error for missing credential key")
	}
}

func TestBuildBundleSecretData_HeadersFromSecretNotFound(t *testing.T) {
	c := fake.NewClientBuilder().Build()

	if _, err := buildBundleSecretData(context.Background(), c, "user-ns",
		nil, &podtracev1alpha1.LocalObjectReference{Name: "absent-headers"}); err == nil {
		t.Fatal("expected error when headersFromSecret is not found")
	}
}

func TestBuildBundleSecretData_NoSourcesReturnsNil(t *testing.T) {
	c := fake.NewClientBuilder().Build()

	got, err := buildBundleSecretData(context.Background(), c, "user-ns", nil, nil)
	if err != nil {
		t.Fatalf("buildBundleSecretData: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil map when neither credRef nor headersFrom is set, got %v", got)
	}
}
