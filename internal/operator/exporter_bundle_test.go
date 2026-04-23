package operator

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	podtracev1alpha1 "github.com/podtrace/podtrace/api/v1alpha1"
)

func ec(name string, spec podtracev1alpha1.ExporterConfigSpec) *podtracev1alpha1.ExporterConfig {
	return &podtracev1alpha1.ExporterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default", UID: types.UID("u-" + name)},
		Spec:       spec,
	}
}

func TestRenderBundlePayload_OTLP_LiteralHeaders(t *testing.T) {
	data, secret, err := renderBundlePayload(ec("otlp-lit", podtracev1alpha1.ExporterConfigSpec{
		Type: podtracev1alpha1.ExporterTypeOTLP,
		OTLP: &podtracev1alpha1.OTLPExporter{
			Endpoint: "otel:4318",
			Protocol: podtracev1alpha1.OTLPProtocolGRPC,
			Insecure: true,
			Headers: []podtracev1alpha1.OTLPHeader{
				{Name: "X-Tenant", Value: "team-a"},
				{Name: "X-Env", Value: "prod"},
			},
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if secret != nil {
		t.Errorf("OTLP without ValueFrom must not produce a credential Secret ref")
	}
	for k, v := range map[string]string{
		"type":             "otlp",
		"endpoint":         "otel:4318",
		"protocol":         "grpc",
		"insecure":         "true",
		"headers.X-Tenant": "team-a",
		"headers.X-Env":    "prod",
	} {
		if data[k] != v {
			t.Errorf("data[%q]=%q want %q", k, data[k], v)
		}
	}
}

func TestRenderBundlePayload_OTLP_SecretBackedHeader(t *testing.T) {
	data, secret, err := renderBundlePayload(ec("otlp-sec", podtracev1alpha1.ExporterConfigSpec{
		Type: podtracev1alpha1.ExporterTypeOTLP,
		OTLP: &podtracev1alpha1.OTLPExporter{
			Endpoint: "otel:4318",
			Headers: []podtracev1alpha1.OTLPHeader{
				{Name: "Authorization", ValueFrom: &podtracev1alpha1.SecretKeySelector{
					Name: "auth", Key: "token",
				}},
			},
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if secret == nil || secret.Name != "auth" || secret.Key != "token" {
		t.Fatalf("expected credential ref auth/token, got %+v", secret)
	}
	if data["header_secret_name"] != "Authorization" {
		t.Errorf("header_secret_name=%q want Authorization", data["header_secret_name"])
	}
	if data["protocol"] != "http" {
		t.Errorf("protocol defaulted wrong: %q", data["protocol"])
	}
}

func TestRenderBundlePayload_Jaeger_NoCredentials(t *testing.T) {
	data, secret, err := renderBundlePayload(ec("j", podtracev1alpha1.ExporterConfigSpec{
		Type:   podtracev1alpha1.ExporterTypeJaeger,
		Jaeger: &podtracev1alpha1.JaegerExporter{Endpoint: "http://jaeger:14268"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if secret != nil {
		t.Error("Jaeger has no credentials; Secret ref must be nil")
	}
	if data["endpoint"] != "http://jaeger:14268" || data["type"] != "jaeger" {
		t.Errorf("payload wrong: %v", data)
	}
}

func TestRenderBundlePayload_Zipkin(t *testing.T) {
	data, secret, err := renderBundlePayload(ec("z", podtracev1alpha1.ExporterConfigSpec{
		Type:   podtracev1alpha1.ExporterTypeZipkin,
		Zipkin: &podtracev1alpha1.ZipkinExporter{Endpoint: "http://zipkin:9411/api/v2/spans"},
	}))
	if err != nil || secret != nil || data["type"] != "zipkin" {
		t.Fatalf("zipkin payload: err=%v secret=%v data=%v", err, secret, data)
	}
}

func TestRenderBundlePayload_Splunk_RequiresTokenSecret(t *testing.T) {
	data, secret, err := renderBundlePayload(ec("s", podtracev1alpha1.ExporterConfigSpec{
		Type: podtracev1alpha1.ExporterTypeSplunk,
		Splunk: &podtracev1alpha1.SplunkExporter{
			Endpoint:       "https://splunk:8088",
			TokenSecretRef: podtracev1alpha1.SecretKeySelector{Name: "hec", Key: "token"},
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if secret == nil || secret.Name != "hec" {
		t.Fatalf("expected HEC credential ref, got %+v", secret)
	}
	if data["endpoint"] != "https://splunk:8088" {
		t.Errorf("splunk endpoint lost: %v", data)
	}
}

func TestRenderBundlePayload_DataDog_DefaultSite(t *testing.T) {
	data, secret, err := renderBundlePayload(ec("d", podtracev1alpha1.ExporterConfigSpec{
		Type: podtracev1alpha1.ExporterTypeDataDog,
		DataDog: &podtracev1alpha1.DataDogExporter{
			APIKeySecretRef: podtracev1alpha1.SecretKeySelector{Name: "dd", Key: "api"},
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if secret == nil || secret.Name != "dd" {
		t.Fatalf("expected DataDog credential ref, got %+v", secret)
	}
	if data["site"] != "datadoghq.com" {
		t.Errorf("default site should be datadoghq.com, got %q", data["site"])
	}
}

func TestRenderBundlePayload_ErrorOnMissingVariant(t *testing.T) {
	_, _, err := renderBundlePayload(ec("broken", podtracev1alpha1.ExporterConfigSpec{
		Type: podtracev1alpha1.ExporterTypeOTLP,
		// no OTLP block populated
	}))
	if err == nil {
		t.Fatal("expected error when spec.otlp is nil for type=otlp")
	}
}

func TestRenderBundlePayload_UnknownType(t *testing.T) {
	_, _, err := renderBundlePayload(ec("xxx", podtracev1alpha1.ExporterConfigSpec{
		Type: podtracev1alpha1.ExporterType("made-up"),
	}))
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestRenderBundlePayload_SamplePercent(t *testing.T) {
	pct := int32(25)
	data, _, err := renderBundlePayload(ec("s", podtracev1alpha1.ExporterConfigSpec{
		Type:          podtracev1alpha1.ExporterTypeJaeger,
		Jaeger:        &podtracev1alpha1.JaegerExporter{Endpoint: "j:14268"},
		SamplePercent: &pct,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if data["sample_percent"] != "25" {
		t.Errorf("sample_percent=%q want 25", data["sample_percent"])
	}
}
