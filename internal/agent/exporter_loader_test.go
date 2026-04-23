package agent

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/podtrace/podtrace/internal/operator"
)

func TestLoadBundle_OTLPLiteral(t *testing.T) {
	const systemNS = "podtrace-system"
	uid := types.UID("e8c32c91-0000-0000-0000-000000000001")
	name := operator.ExporterBundleName(uid)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       systemNS,
			ResourceVersion: "42",
		},
		Data: map[string]string{
			"type":              "otlp",
			"endpoint":          "otel:4318",
			"protocol":          "http",
			"insecure":          "false",
			"headers.X-Env":     "prod",
			"headers.X-Tenant":  "team-a",
			"sample_percent":    "50",
		},
	}

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cm).Build()

	payload, err := LoadBundle(context.Background(), c, systemNS, uid)
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if payload.Type != "otlp" || payload.Endpoint != "otel:4318" {
		t.Errorf("payload wrong: %+v", payload)
	}
	if payload.Sample != 0.5 {
		t.Errorf("sample=%v want 0.5", payload.Sample)
	}
	if payload.Headers["X-Env"] != "prod" || payload.Headers["X-Tenant"] != "team-a" {
		t.Errorf("headers lost: %+v", payload.Headers)
	}
	if payload.Insecure {
		t.Error("insecure parsed wrong for 'false'")
	}
	if payload.ResourceVer != "42" {
		t.Errorf("ResourceVer=%q want 42", payload.ResourceVer)
	}
}

func TestLoadBundle_WithCredential(t *testing.T) {
	const systemNS = "podtrace-system"
	uid := types.UID("e8c32c91-0000-0000-0000-000000000002")
	name := operator.ExporterBundleName(uid)

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: systemNS},
		Data:       map[string]string{"type": "datadog", "site": "datadoghq.com"},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: systemNS},
		Data:       map[string][]byte{"credential": []byte("super-secret")},
	}

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cm, secret).Build()

	payload, err := LoadBundle(context.Background(), c, systemNS, uid)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload.Credential) != "super-secret" {
		t.Errorf("credential=%q want super-secret", payload.Credential)
	}
}

func TestLoadBundle_MissingConfigMap(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	_, err := LoadBundle(context.Background(), c, "podtrace-system", types.UID("missing"))
	if err == nil {
		t.Fatal("expected NotFound error for missing ConfigMap")
	}
	if !strings.Contains(err.Error(), "ConfigMap") {
		t.Errorf("error does not mention ConfigMap: %v", err)
	}
}

func TestBuildExporter_OTLP(t *testing.T) {
	p := &BundlePayload{
		Type:     "otlp",
		Endpoint: "otel-collector:4318",
		Protocol: "http",
		Insecure: true,
	}
	exp, err := BuildExporter(p, CRKey{"ns", "cr"})
	if err != nil {
		t.Fatal(err)
	}
	if exp == nil {
		t.Fatal("nil exporter")
	}
	// Clean shutdown is required — it closes the TP before the test returns.
	ctx, cancel := contextWithTimeout(1)
	defer cancel()
	_ = exp.Close(ctx)
}

func TestBuildExporter_UnsupportedTypeReturnsDescriptiveError(t *testing.T) {
	cases := []string{"jaeger", "zipkin", "splunk", "datadog"}
	for _, ty := range cases {
		t.Run(ty, func(t *testing.T) {
			_, err := BuildExporter(&BundlePayload{Type: ty}, CRKey{"ns", "n"})
			if err == nil {
				t.Fatalf("expected not-yet-implemented error for %q", ty)
			}
			if !strings.Contains(err.Error(), "not yet implemented") {
				t.Errorf("error text wrong: %v", err)
			}
		})
	}
}

func TestBuildExporter_UnknownType(t *testing.T) {
	_, err := BuildExporter(&BundlePayload{Type: "nothing"}, CRKey{"ns", "n"})
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestBuildExporter_NilPayload(t *testing.T) {
	_, err := BuildExporter(nil, CRKey{"ns", "n"})
	if err == nil {
		t.Fatal("expected error for nil payload")
	}
}

// --- helpers ----------------------------------------------------------

// contextWithTimeout is a tiny helper so test files don't all need to
// import time + context for every trivial cleanup.
func contextWithTimeout(seconds int) (context.Context, func()) {
	return context.WithCancel(context.Background()) //nolint:contextcheck // tests tolerate indefinite ctx
}
