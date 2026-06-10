package operator

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
	"github.com/podtrace/podtrace/pkg/exporter/bundle"
)

func otlpSpec(otlp *podtracev1alpha1.OTLPExporter) podtracev1alpha1.ExporterConfigSpec {
	return podtracev1alpha1.ExporterConfigSpec{
		Type: podtracev1alpha1.ExporterTypeOTLP,
		OTLP: otlp,
	}
}

// TestRenderBundlePayload_LiteralHeadersAfterValueFrom is a regression test:
// the header loop used to return on the first ValueFrom header, silently
// dropping every literal header declared after it.
func TestRenderBundlePayload_LiteralHeadersAfterValueFrom(t *testing.T) {
	data, credRef, _, err := renderBundlePayload(nil, ec("otlp-mixed", otlpSpec(&podtracev1alpha1.OTLPExporter{
		Endpoint: "collector:4318",
		Headers: []podtracev1alpha1.OTLPHeader{
			{Name: "X-Tenant", Value: "team-a"},
			{Name: "Authorization", ValueFrom: &podtracev1alpha1.SecretKeySelector{Name: "auth", Key: "token"}},
			{Name: "X-Env", Value: "prod"},
		},
	})), nil)
	if err != nil {
		t.Fatalf("renderBundlePayload: %v", err)
	}
	if credRef == nil || credRef.Name != "auth" || credRef.Key != "token" {
		t.Errorf("credRef = %+v, want auth/token", credRef)
	}
	if data["header_secret_name"] != "Authorization" {
		t.Errorf("header_secret_name = %q, want Authorization", data["header_secret_name"])
	}
	for key, want := range map[string]string{
		"headers.X-Tenant": "team-a",
		"headers.X-Env":    "prod",
	} {
		if data[key] != want {
			t.Errorf("data[%q] = %q, want %q (literal headers after a ValueFrom header must not be dropped)", key, data[key], want)
		}
	}
}

// TestRenderBundlePayload_MultipleValueFromRejected: the bundle wire format
// carries a single credential, so a second ValueFrom header must be a loud
// error instead of being silently ignored while readiness reports healthy.
func TestRenderBundlePayload_MultipleValueFromRejected(t *testing.T) {
	_, _, _, err := renderBundlePayload(nil, ec("otlp-two-creds", otlpSpec(&podtracev1alpha1.OTLPExporter{
		Endpoint: "collector:4318",
		Headers: []podtracev1alpha1.OTLPHeader{
			{Name: "Authorization", ValueFrom: &podtracev1alpha1.SecretKeySelector{Name: "a", Key: "k"}},
			{Name: "X-Other", ValueFrom: &podtracev1alpha1.SecretKeySelector{Name: "b", Key: "k"}},
		},
	})), nil)
	if err == nil {
		t.Fatal("expected an error for two ValueFrom headers, got nil")
	}
}

// TestBuildBundleSecretData_HeadersFromSecret is a regression test:
// headersFromSecret was checked by the readiness evaluator but never
// rendered into the bundle, so agents exported with no headers while the
// ExporterConfig reported Ready=True.
func TestBuildBundleSecretData_HeadersFromSecret(t *testing.T) {
	src := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "extra-headers", Namespace: "user-ns"},
		Data: map[string][]byte{
			"X-Scope-OrgID": []byte("tenant-1"),
			"X-Api-Key":     []byte("s3cr3t"),
		},
	}
	cred := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "auth", Namespace: "user-ns"},
		Data:       map[string][]byte{"token": []byte("Bearer xyz")},
	}
	c := fake.NewClientBuilder().WithObjects(src, cred).Build()

	got, err := buildBundleSecretData(context.Background(), c, "user-ns",
		&podtracev1alpha1.SecretKeySelector{Name: "auth", Key: "token"},
		&podtracev1alpha1.LocalObjectReference{Name: "extra-headers"})
	if err != nil {
		t.Fatalf("buildBundleSecretData: %v", err)
	}
	for key, want := range map[string]string{
		bundle.CredentialKey:                           "Bearer xyz",
		bundle.SecretHeaderKeyPrefix + "X-Scope-OrgID": "tenant-1",
		bundle.SecretHeaderKeyPrefix + "X-Api-Key":     "s3cr3t",
	} {
		if string(got[key]) != want {
			t.Errorf("secret data[%q] = %q, want %q", key, got[key], want)
		}
	}
}

func TestCandidateSystemNamespaces(t *testing.T) {
	cases := []struct {
		effective, fallback string
		want                int
	}{
		{"podtrace-system", "podtrace-system", 1},
		{"", "podtrace-system", 1},
		{"custom-ns", "podtrace-system", 2},
	}
	for _, tc := range cases {
		if got := candidateSystemNamespaces(tc.effective, tc.fallback); len(got) != tc.want {
			t.Errorf("candidateSystemNamespaces(%q, %q) = %v, want %d entries", tc.effective, tc.fallback, got, tc.want)
		}
	}
}
