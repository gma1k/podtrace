package v1alpha1_test

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	podtracev1alpha1 "github.com/gma1k/podtrace/api/v1alpha1"
)

func TestNoExporterVariantSkipsTheEndpointCheck(t *testing.T) {
	cases := map[string]podtracev1alpha1.ExporterConfigSpec{
		"otlp": {
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "ftp://collector:4318"},
		},
		"jaeger": {
			Type:   podtracev1alpha1.ExporterTypeJaeger,
			Jaeger: &podtracev1alpha1.JaegerExporter{Endpoint: "ftp://jaeger:4318"},
		},
		"zipkin": {
			Type:   podtracev1alpha1.ExporterTypeZipkin,
			Zipkin: &podtracev1alpha1.ZipkinExporter{Endpoint: "ftp://zipkin:9411"},
		},
		"splunk": {
			Type: podtracev1alpha1.ExporterTypeSplunk,
			Splunk: &podtracev1alpha1.SplunkExporter{
				Endpoint:       "ftp://splunk:8088",
				TokenSecretRef: podtracev1alpha1.SecretKeySelector{Name: "s", Key: "k"},
			},
		},
		"datadog": {
			Type: podtracev1alpha1.ExporterTypeDataDog,
			DataDog: &podtracev1alpha1.DataDogExporter{
				Endpoint:        "ftp://dd:4318",
				APIKeySecretRef: podtracev1alpha1.SecretKeySelector{Name: "s", Key: "k"},
			},
		},
	}

	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			err := podtracev1alpha1.ValidateExporterConfigVariant(spec)
			if err == nil {
				t.Fatalf("%s accepted an ftp:// endpoint. Every variant must reach the scheme "+
					"allowlist, or one backend becomes a hole through which a tenant sends "+
					"telemetry over an unintended protocol", name)
			}
			if !strings.Contains(err.Error(), "scheme must be http or https") {
				t.Errorf("%s rejected with %q, want the scheme message", name, err)
			}
		})
	}
}

func TestUnparseableEndpointIsReportedNotIgnored(t *testing.T) {
	err := podtracev1alpha1.ValidateExporterConfigVariant(podtracev1alpha1.ExporterConfigSpec{
		Type: podtracev1alpha1.ExporterTypeOTLP,
		OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "http://[::1"},
	})
	if err == nil {
		t.Fatal("an unparseable endpoint was accepted")
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("error %q does not report the parse failure", err)
	}
}

func TestBareHostPortIsTreatedAsHTTP(t *testing.T) {
	for _, endpoint := range []string{"collector:4318", "collector.observability:4318", ""} {
		spec := podtracev1alpha1.ExporterConfigSpec{
			Type: podtracev1alpha1.ExporterTypeOTLP,
			OTLP: &podtracev1alpha1.OTLPExporter{
				Endpoint:          endpoint,
				HeadersFromSecret: &corev1.LocalObjectReference{Name: "extra"},
			},
		}
		if err := podtracev1alpha1.ValidateExporterConfigVariant(spec); err != nil {
			t.Errorf("endpoint %q was rejected: %v. A bare host:port is what the exporter "+
				"constructors normalise to http://, so validation must accept it", endpoint, err)
		}
	}
}

func TestEndpointThatOnlyFailsOnceNormalisedIsReported(t *testing.T) {
	err := podtracev1alpha1.ValidateExporterConfigVariant(podtracev1alpha1.ExporterConfigSpec{
		Type: podtracev1alpha1.ExporterTypeOTLP,
		OTLP: &podtracev1alpha1.OTLPExporter{Endpoint: "collector 4318"},
	})
	if err == nil {
		t.Fatal("an endpoint that parses bare but not once prefixed with http:// was accepted. " +
			"The scheme check re-parses a bare host:port as http://, and a failure there must " +
			"surface rather than fall through as valid")
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("error %q does not report the parse failure", err)
	}
}
