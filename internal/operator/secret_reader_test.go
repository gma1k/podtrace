package operator

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestReaderAccessors_OverrideAndFallback(t *testing.T) {
	scheme := newOperatorScheme(t)
	cached := fake.NewClientBuilder().WithScheme(scheme).Build()
	direct := fake.NewClientBuilder().WithScheme(scheme).Build()

	checks := []struct {
		name       string
		withReader func(apiReader client.Reader) client.Reader
	}{
		{"podtrace", func(a client.Reader) client.Reader {
			return (&PodTraceReconciler{Client: cached, APIReader: a}).reader()
		}},
		{"session", func(a client.Reader) client.Reader {
			return (&PodTraceSessionReconciler{Client: cached, APIReader: a}).reader()
		}},
		{"exporterconfig", func(a client.Reader) client.Reader {
			return (&ExporterConfigReconciler{Client: cached, APIReader: a}).reader()
		}},
	}
	for _, c := range checks {
		if got := c.withReader(direct); got != client.Reader(direct) {
			t.Errorf("%s: reader() must return APIReader when set", c.name)
		}
		if got := c.withReader(nil); got != client.Reader(cached) {
			t.Errorf("%s: reader() must fall back to the cached Client when APIReader is nil", c.name)
		}
	}
}

func TestEvaluateReadiness_ReadsCredentialViaAPIReaderNotStrippedCache(t *testing.T) {
	scheme := newOperatorScheme(t)

	strippedCache := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "auth", Namespace: "ns"}},
	).Build()
	apiReader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "auth", Namespace: "ns"},
			Data:       map[string][]byte{"token": []byte("s3cr3t")},
		},
	).Build()

	ec := &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "otlp", Namespace: "ns"},
		Spec: podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{
				Endpoint: "o:4317",
				Headers: []podtracev1alpha1.OTLPHeader{
					{Name: "X-Auth", ValueFrom: &podtracev1alpha1.SecretKeySelector{Name: "auth", Key: "token"}},
				},
			},
		},
	}

	r := &ExporterConfigReconciler{Client: strippedCache, APIReader: apiReader, Scheme: scheme}
	ready, _, reason, msg := r.evaluateReadiness(context.Background(), ec)
	if !ready {
		t.Fatalf("readiness must resolve the key via the APIReader, got not-ready reason=%s msg=%q", reason, msg)
	}
	if reason != ecReasonSecretsResolved {
		t.Errorf("reason = %q, want %q (reading the stripped cache would report SecretKeyMissing)", reason, ecReasonSecretsResolved)
	}
}

func TestBuildBundleSecretData_ResolvesFromReader(t *testing.T) {
	scheme := newOperatorScheme(t)
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "auth", Namespace: "team-a"},
			Data:       map[string][]byte{"token": []byte("s3cr3t")},
		},
	).Build()

	data, err := buildBundleSecretData(context.Background(), reader, "team-a",
		&podtracev1alpha1.SecretKeySelector{Name: "auth", Key: "token"}, nil)
	if err != nil {
		t.Fatalf("buildBundleSecretData: %v", err)
	}
	if string(data["credential"]) != "s3cr3t" {
		t.Errorf("credential = %q, want the plaintext read from the reader", data["credential"])
	}
}
